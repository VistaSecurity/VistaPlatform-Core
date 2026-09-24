package catalogfeeds

import "time"

// maxStoredErrorLen caps error text stored in catalog_feed_state: a wrapped
// HTTP error can carry a whole response body, and the column is read straight
// into an admin table cell.
const maxStoredErrorLen = 1000

func capErrorText(msg string) string {
	if len(msg) > maxStoredErrorLen {
		return msg[:maxStoredErrorLen] + "…"
	}
	return msg
}

// nextFeedState is the ONE rule for what a finished run writes to
// catalog_feed_state. SQLStore.MarkResult and the test stub both call it, so
// the stub cannot drift from the store on the rule that matters most:
//
//   - The cursor advances on success. On failure it stays where it was —
//     UNLESS the feed reports PartialProgress, meaning its cursor holds only
//     completed units (OSV's per-ecosystem watermarks). Then it is persisted,
//     so one failing ecosystem no longer throws away the others' progress and
//     forces every ecosystem to re-download on the next run (RC-29).
//   - row_count is what the run measurably wrote, failed or not. Those rows
//     are committed; reporting 0 for a run that wrote thousands hid the
//     progress it did make.
//   - Per-ecosystem status is replaced by this run's list, carrying each
//     ecosystem's last success forward so a failing one still says when it
//     last worked. A run that reports no ecosystems (another feed, or a run
//     that died before reaching any) leaves the previous list untouched.
func nextFeedState(prev FeedState, res SyncResult, runErr error, now time.Time) FeedState {
	next := prev
	next.LastRunAt = &now
	next.RowCount = res.Rows

	cursorMayMove := runErr == nil || res.PartialProgress
	if cursorMayMove && res.Cursor != "" {
		c := res.Cursor
		next.Cursor = &c
	}

	if runErr != nil {
		next.LastStatus = StatusError
		msg := capErrorText(runErr.Error())
		next.LastError = &msg
	} else {
		next.LastStatus = StatusOK
		next.LastError = nil
	}

	if len(res.Ecosystems) > 0 {
		lastSuccess := map[string]*time.Time{}
		for _, e := range prev.Ecosystems {
			lastSuccess[e.Name] = e.LastSuccessAt
		}
		merged := make([]EcosystemStatus, 0, len(res.Ecosystems))
		for _, e := range res.Ecosystems {
			e.LastRunAt = &now
			if e.Status == EcosystemOK {
				e.LastSuccessAt = &now
			} else {
				e.LastSuccessAt = lastSuccess[e.Name]
			}
			if e.LastError != nil {
				msg := capErrorText(*e.LastError)
				e.LastError = &msg
			}
			merged = append(merged, e)
		}
		next.Ecosystems = merged
	}
	if next.Ecosystems == nil {
		next.Ecosystems = []EcosystemStatus{}
	}
	return next
}
