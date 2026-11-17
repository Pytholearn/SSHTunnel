package main

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// LogBuffer keeps the last N log lines and forwards new lines to a sink.
type LogBuffer struct {
	mu    sync.Mutex
	lines []string
	max   int
	sink  func(line string)
}

func NewLogBuffer(max int) *LogBuffer { return &LogBuffer{max: max} }

func (l *LogBuffer) SetSink(f func(string)) {
	l.mu.Lock()
	l.sink = f
	l.mu.Unlock()
}

func (l *LogBuffer) Printf(format string, args ...any) {
	line := time.Now().Format("15:04:05") + " " + strings.TrimSpace(fmt.Sprintf(format, args...))
	l.mu.Lock()
	l.lines = append(l.lines, line)
	if len(l.lines) > l.max {
		l.lines = append([]string(nil), l.lines[len(l.lines)-l.max:]...)
	}
	sink := l.sink
	l.mu.Unlock()
	if sink != nil {
		sink(line)
	}
}

func (l *LogBuffer) Lines() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.lines...)
}
