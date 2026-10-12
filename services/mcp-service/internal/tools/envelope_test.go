package tools

import (
	"encoding/json"
	"testing"
)

func TestEnvelopeLabelsAndTruncatesLongestArray(t *testing.T) {
	rows := make([]any, 1000)
	for i := range rows {
		rows[i] = map[string]any{"name": "x", "pad": "0123456789012345678901234567890123456789"}
	}
	in := map[string]any{"total": 1000, "items": rows, "small": []any{1, 2}, "next_cursor": "c"}
	out, b, counted, truncated, err := envelope(in, 4096)
	if err != nil || !truncated {
		t.Fatalf("truncated=%v err=%v", truncated, err)
	}
	if len(b) > 4096 {
		t.Fatalf("len = %d", len(b))
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m["truncated"] != true || m["data_origin"] != DataOrigin || m["total"] != float64(1000) {
		t.Fatalf("got %v", m)
	}
	if _, ok := m["next_cursor"]; ok {
		t.Error("next_cursor kept")
	}
	if len(m["small"].([]any)) != 2 {
		t.Error("the short array should be left alone")
	}
	_ = out
	_ = counted
}

func TestEnvelopeWrapsArraysAndLeavesSmallResultsAlone(t *testing.T) {
	_, b, _, truncated, err := envelope([]any{1, 2, 3}, 1024)
	if err != nil || truncated {
		t.Fatal(err, truncated)
	}
	if string(b) != `{"data":[1,2,3],"data_origin":"tenant-inventory, untrusted"}` {
		t.Fatalf("got %s", b)
	}
}

func TestEnvelopeRefusesWhatCannotBeShortened(t *testing.T) {
	_, b, _, truncated, _ := envelope(map[string]any{"blob": string(make([]byte, 10000))}, 512)
	if !truncated || len(b) > 512 {
		t.Fatalf("truncated=%v len=%d", truncated, len(b))
	}
}

func TestClampOffsetAndPage(t *testing.T) {
	if clampOffset(-5) != 0 || clampOffset(10) != 10 || clampOffset(1<<40) != maxOffset {
		t.Fatal("clampOffset")
	}
	if p, _ := clampPage(1<<40, 5); p != "10000" {
		t.Fatalf("page = %s", p)
	}
	if _, err := cursorPage(encodeCursor(maxPage + 1)); err == nil {
		t.Fatal("out-of-range cursor accepted")
	}
}
