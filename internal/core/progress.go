package core

import "context"

// Progress is a live operator hint. It is not evidence. Collection records,
// manifests and reports omit it. A nil reporter makes every update a no-op.
type Progress struct {
	Phase      string
	Detail     string
	Step       int
	Steps      int
	Bytes      int64
	TotalBytes int64
}

type progressKey struct{}

// WithProgress attaches an operator reporter to ctx. The function must be safe
// to call often and must not retain the Progress value's backing data.
func WithProgress(ctx context.Context, report func(Progress)) context.Context {
	if ctx == nil || report == nil {
		return ctx
	}
	return context.WithValue(ctx, progressKey{}, report)
}

func progressEnabled(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	_, ok := ctx.Value(progressKey{}).(func(Progress))
	return ok
}

// ReportProgress delivers one hint when ctx carries a reporter.
func ReportProgress(ctx context.Context, p Progress) {
	if ctx == nil {
		return
	}
	report, _ := ctx.Value(progressKey{}).(func(Progress))
	if report != nil {
		report(p)
	}
}
