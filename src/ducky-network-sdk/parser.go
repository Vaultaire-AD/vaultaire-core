package duckynetwork

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
)

type ParserFunc func(Frame) (any, error)

// CoreInfo représente un Core retourné par 04_04.
type CoreInfo struct {
	Hostname     string
	IP           string
	Version      string
	Capabilities string
}

type Registry struct {
	mu      sync.RWMutex
	parsers map[string]ParserFunc
}

func NewRegistry() *Registry {
	r := &Registry{parsers: map[string]ParserFunc{}}
	r.Register(Trame04_04, parseCoreList)
	return r
}

func (r *Registry) Register(code string, parser ParserFunc) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.parsers[code] = parser
}

func (r *Registry) Parse(frame Frame) (any, error) {
	r.mu.RLock()
	parser, ok := r.parsers[frame.Code]
	r.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("no parser registered for %s", frame.Code)
	}
	return parser(frame)
}

func parseCoreList(frame Frame) (any, error) {
	lines := strings.Split(frame.Content, "\n")
	if len(lines) == 0 {
		return []CoreInfo{}, nil
	}
	count, _ := strconv.Atoi(strings.TrimSpace(lines[0]))
	out := make([]CoreInfo, 0, count)
	for i := 1; i < len(lines) && len(out) < count; i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) < 2 {
			continue
		}
		item := CoreInfo{Hostname: parts[0], IP: parts[1]}
		if len(parts) >= 3 {
			item.Version = parts[2]
		}
		if len(parts) >= 4 {
			item.Capabilities = parts[3]
		}
		out = append(out, item)
	}
	return out, nil
}
