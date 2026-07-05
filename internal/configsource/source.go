package configsource

import (
	"sync"
	"sync/atomic"

	"mscope-hysteria/pkg/control"
)

type Source struct {
	mu      sync.RWMutex
	current atomic.Pointer[control.ConfigPayload]
}

func New() *Source {
	return &Source{}
}

func (s *Source) Apply(p control.ConfigPayload) error {
	s.mu.Lock()
	s.current.Store(&p)
	s.mu.Unlock()
	return nil
}

func (s *Source) Current() (control.ConfigPayload, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p := s.current.Load()
	if p == nil {
		return control.ConfigPayload{}, false
	}
	return *p, true
}
