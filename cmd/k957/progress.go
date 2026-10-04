package main

import (
	"context"
	"fmt"
	"io"
	"k957/internal/core"
	"os"
	"strings"
	"time"
	"unicode/utf8"
)

type progressPhase struct {
	ID     string
	Weight int
}

type progressView struct {
	out        io.Writer
	tty        bool
	color      bool
	command    string
	phases     []progressPhase
	started    time.Time
	lastDraw   time.Time
	lastPhase  string
	lastBucket int
	lines      int
	hidden     bool
	closed     bool
	failed     bool
	saw        bool
	last       core.Progress
}

func attachProgress(ctx context.Context, command string, phases []progressPhase) (context.Context, *progressView) {
	view := newProgressView(os.Stderr, command, phases)
	return core.WithProgress(ctx, view.report), view
}

func newProgressView(out io.Writer, command string, phases []progressPhase) *progressView {
	tty := supportsANSI(out)
	return &progressView{
		out: out, tty: tty, color: tty && os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb",
		command: command, phases: phases, started: time.Now(),
	}
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	return terminalFile(f)
}

func (v *progressView) report(p core.Progress) {
	if v == nil || v.closed {
		return
	}
	v.last = p
	v.saw = true
	now := time.Now()
	frac, known := overallFraction(v.phases, p)
	bucket := int(frac * 20)
	if v.tty {
		if p.Phase == v.lastPhase && now.Sub(v.lastDraw) < 100*time.Millisecond {
			return
		}
	} else if p.Phase == v.lastPhase && bucket == v.lastBucket && now.Sub(v.lastDraw) < 2*time.Second {
		return
	}
	v.lastPhase = p.Phase
	v.lastBucket = bucket
	v.lastDraw = now
	v.paint(v.frame(p, frac, known, now.Sub(v.started), false))
}

func (v *progressView) done() {
	if v == nil || v.closed || v.failed || !v.saw {
		return
	}
	v.paint(v.frame(v.last, 1, true, time.Since(v.started), true))
}

func (v *progressView) fail() {
	if v == nil || v.closed || !v.saw {
		return
	}
	v.failed = true
	frac, known := overallFraction(v.phases, v.last)
	v.paint(v.frame(v.last, frac, known, time.Since(v.started), false))
}

func (v *progressView) finish() {
	if v == nil || v.closed {
		return
	}
	v.closed = true
	if v.hidden {
		fmt.Fprint(v.out, "\x1b[?25h")
	}
}

func (v *progressView) paint(lines []string) {
	if v.tty {
		if !v.hidden {
			fmt.Fprint(v.out, "\x1b[?25l")
			v.hidden = true
		}
		if v.lines > 0 {
			fmt.Fprintf(v.out, "\x1b[%dA", v.lines)
		}
		for _, line := range lines {
			fmt.Fprintf(v.out, "\x1b[2K%s\n", line)
		}
		for v.lines > len(lines) {
			fmt.Fprint(v.out, "\x1b[2K\n")
			lines = append(lines, "")
		}
		v.lines = len(lines)
		return
	}
	if len(lines) > 0 {
		fmt.Fprintln(v.out, lines[0])
	}
}

func (v *progressView) frame(p core.Progress, frac float64, known bool, elapsed time.Duration, done bool) []string {
	title := "k957 " + v.command
	if v.failed {
		title += "  failed  " + formatDuration(elapsed)
	} else if done {
		title += "  finished  " + formatDuration(elapsed)
	}
	flow := v.flow(p.Phase, done)
	bar := v.bar(frac, known, p, elapsed, done)
	detail := v.detail(p, done)
	if v.tty {
		return []string{fit(title, 78), fit(flow, 78), fit(bar, 78), fit(detail, 78)}
	}
	return []string{fit(strings.TrimSpace(title+"  "+bar+"  "+detail), 160)}
}

func (v *progressView) flow(current string, done bool) string {
	if len(v.phases) == 0 {
		return ""
	}
	seen := false
	for _, ph := range v.phases {
		if ph.ID == current {
			seen = true
		}
	}
	var b strings.Builder
	beforeCurrent := seen
	for i, ph := range v.phases {
		if i > 0 {
			b.WriteString("  ")
		}
		doneMark, currentMark, pendingMark := "+", ">", "·"
		if v.tty {
			doneMark, currentMark, pendingMark = "✓", "●", "·"
		}
		mark := pendingMark
		label := phaseLabel(ph.ID)
		switch {
		case v.failed && (ph.ID == current || !seen && i == len(v.phases)-1):
			mark = "!"
			if v.tty {
				mark = "✗"
			}
			label = v.paintWarn(label)
		case done:
			mark = doneMark
			label = v.paintDone(label)
		case seen && ph.ID == current:
			mark = currentMark
			beforeCurrent = false
			label = v.paintCurrent(label)
		case beforeCurrent:
			mark = doneMark
			label = v.paintDone(label)
		default:
			label = v.paintPending(label)
		}
		b.WriteString(mark)
		b.WriteByte(' ')
		b.WriteString(label)
	}
	return b.String()
}

func (v *progressView) bar(frac float64, known bool, p core.Progress, elapsed time.Duration, done bool) string {
	const width = 24
	fillChar, emptyChar, pulse := "#", "-", "o"
	if v.tty {
		fillChar, emptyChar, pulse = "█", "░", "●"
	}
	if !known && !done {
		pos := 0
		if p.Step > 0 {
			pos = (p.Step - 1) % width
		}
		cells := strings.Repeat(emptyChar, pos) + pulse + strings.Repeat(emptyChar, width-pos-1)
		return "[" + cells + "]  " + v.paintWarn("estimating")
	}
	if frac < 0 {
		frac = 0
	}
	if frac > 1 {
		frac = 1
	}
	fill := int(frac*float64(width) + 0.5)
	if done {
		fill = width
	}
	if fill > width {
		fill = width
	}
	bar := strings.Repeat(fillChar, fill) + strings.Repeat(emptyChar, width-fill)
	percent := fmt.Sprintf("%3.0f%%", frac*100)
	if done || frac >= 1 {
		percent = "100%"
	}
	eta := "estimating"
	if done || frac >= 1 {
		eta = formatDuration(elapsed)
	} else if remain, ok := estimateRemaining(elapsed, frac); ok {
		eta = "est. " + formatDuration(remain)
	}
	return "[" + v.paintMeter(bar, done || frac >= 1) + "]  " + percent + "  " + eta
}

func (v *progressView) detail(p core.Progress, done bool) string {
	byteLabel := ""
	if v.command == "verify" || v.command == "analyze" {
		byteLabel = "read workload "
	}
	if done {
		parts := []string{}
		if p.Steps > 0 {
			parts = append(parts, fmt.Sprintf("%d/%d", p.Steps, p.Steps))
		} else if p.Step > 0 {
			parts = append(parts, fmt.Sprintf("%d", p.Step))
		}
		if p.TotalBytes > 0 {
			parts = append(parts, byteLabel+formatBytes(p.TotalBytes))
		} else if p.Bytes > 0 {
			parts = append(parts, byteLabel+formatBytes(p.Bytes))
		}
		if p.Detail != "" {
			parts = append(parts, oneLine(p.Detail))
		}
		return strings.Join(parts, "  ")
	}
	parts := []string{phaseLabel(p.Phase)}
	if p.Steps > 0 {
		parts = append(parts, fmt.Sprintf("%d/%d", p.Step, p.Steps))
	} else if p.Step > 0 {
		parts = append(parts, fmt.Sprintf("%d", p.Step))
	}
	if p.TotalBytes > 0 {
		parts = append(parts, byteLabel+formatBytes(p.Bytes)+" / "+formatBytes(p.TotalBytes))
	} else if p.Bytes > 0 {
		parts = append(parts, byteLabel+formatBytes(p.Bytes))
	}
	if p.Detail != "" {
		parts = append(parts, oneLine(p.Detail))
	}
	return strings.Join(parts, "  ")
}

func (v *progressView) paintCurrent(s string) string {
	if !v.color {
		return s
	}
	return "\x1b[1m" + s + "\x1b[0m"
}

func (v *progressView) paintDone(s string) string {
	if !v.color {
		return s
	}
	return "\x1b[32m" + s + "\x1b[0m"
}

func (v *progressView) paintPending(s string) string {
	if !v.color {
		return s
	}
	return "\x1b[2m" + s + "\x1b[0m"
}

func (v *progressView) paintWarn(s string) string {
	if !v.color {
		return s
	}
	return "\x1b[33m" + s + "\x1b[0m"
}

func (v *progressView) paintMeter(s string, done bool) string {
	if !v.color {
		return s
	}
	if done {
		return "\x1b[32m" + s + "\x1b[0m"
	}
	return "\x1b[36m" + s + "\x1b[0m"
}

func overallFraction(phases []progressPhase, p core.Progress) (float64, bool) {
	total := 0
	index := -1
	for i, ph := range phases {
		if ph.Weight > 0 {
			total += ph.Weight
		}
		if ph.ID == p.Phase {
			index = i
		}
	}
	sub, subKnown := subFraction(p)
	if index < 0 || total == 0 {
		return sub, subKnown
	}
	before := 0
	for i := 0; i < index; i++ {
		if phases[i].Weight > 0 {
			before += phases[i].Weight
		}
	}
	value := (float64(before) + sub*float64(phases[index].Weight)) / float64(total)
	return clamp01(value), subKnown
}

func subFraction(p core.Progress) (float64, bool) {
	if p.TotalBytes > 0 {
		return clamp01(float64(p.Bytes) / float64(p.TotalBytes)), true
	}
	if p.Steps > 0 {
		return clamp01(float64(p.Step) / float64(p.Steps)), true
	}
	return 0, false
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func estimateRemaining(elapsed time.Duration, frac float64) (time.Duration, bool) {
	if elapsed < time.Second || frac < 0.02 || frac >= 1 {
		return 0, false
	}
	total := time.Duration(float64(elapsed) / frac)
	remain := total - elapsed
	if remain < 0 {
		return 0, true
	}
	return remain, true
}

func phaseLabel(id string) string {
	switch id {
	case "live-system":
		return "live system"
	case "":
		return "working"
	default:
		return id
	}
}

func formatDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second
	switch {
	case h > 0:
		return fmt.Sprintf("%dh%02dm", h, m)
	case m > 0:
		return fmt.Sprintf("%dm%02ds", m, s)
	default:
		return fmt.Sprintf("%ds", s)
	}
}

func formatBytes(n int64) string {
	if n < 0 {
		n = 0
	}
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	value := float64(n)
	unit := 0
	for value >= 1024 && unit < len(units)-1 {
		value /= 1024
		unit++
	}
	if unit == 0 {
		return fmt.Sprintf("%d B", n)
	}
	return fmt.Sprintf("%.1f %s", value, units[unit])
}

func oneLine(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return ' '
		}
		return r
	}, s)
}

func fit(s string, width int) string {
	if width < 4 {
		return s
	}
	plain := stripANSI(s)
	if utf8.RuneCountInString(plain) <= width {
		return s
	}
	// Color is omitted from truncated lines so a cut sequence cannot leak.
	r := []rune(plain)
	return string(r[:width-3]) + "..."
}

func stripANSI(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '[' {
			i += 2
			for i < len(s) && s[i] != 'm' {
				i++
			}
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
