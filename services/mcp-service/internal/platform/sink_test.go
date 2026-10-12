package platform

import (
	"context"

	sharedaudit "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
)

type nopSink struct{}

func (nopSink) LogActivity(context.Context, *sharedaudit.ActivityLogRequest) error { return nil }
