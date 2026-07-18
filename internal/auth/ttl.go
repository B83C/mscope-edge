package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	hcore "github.com/apernet/hysteria/core/v2/server"
	"github.com/B83C/mscope-edge/pkg/control"
)

type grant struct {
	secretHash [32]byte
	expires    time.Time
	maxClients int
}

type userStats struct {
	Tx       atomic.Uint64
	Rx       atomic.Uint64
	Online   atomic.Bool
	LastSeen atomic.Int64
}

type Store struct {
	mu     sync.RWMutex
	grants map[string]grant

	sessionMu sync.Mutex
	active    map[string]int

	statsMu sync.RWMutex
	stats   map[string]*userStats

	OnDisconnect func(id string) // called when a session ends
}

func NewStore() *Store {
	return &Store{
		grants: make(map[string]grant),
		active: make(map[string]int),
		stats:  make(map[string]*userStats),
	}
}

func (s *Store) Apply(payload control.GrantsPayload) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for _, g := range payload.Grants {
		if now.After(g.ExpiresAt) {
			delete(s.grants, g.UserID)
			continue
		}
		s.grants[g.UserID] = grant{
			secretHash: hashSecret(g.Secret),
			expires:    g.ExpiresAt,
			maxClients: g.MaxClients,
		}
	}
	for id, g := range s.grants {
		if now.After(g.expires) {
			delete(s.grants, id)
		}
	}
}

func (s *Store) Revoke(payload control.RevokePayload) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range payload.Users {
		delete(s.grants, id)
	}
}

func (s *Store) SetMaxClients(userID string, max int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if g, ok := s.grants[userID]; ok {
		g.maxClients = max
		s.grants[userID] = g
	}
}

func (s *Store) UserMax(userID string) (int, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if g, ok := s.grants[userID]; ok {
		return g.maxClients, true
	}
	return 0, false
}

func (s *Store) Authenticate(addr net.Addr, auth string, tx uint64) (bool, string) {
	id, secret, ok := parseAuth(auth)
	if !ok {
		return false, ""
	}
	s.mu.RLock()
	g, found := s.grants[id]
	s.mu.RUnlock()
	if !found {
		return false, ""
	}
	if time.Now().After(g.expires) {
		return false, ""
	}
	h := hashSecret(secret)
	if subtle.ConstantTimeCompare(h[:], g.secretHash[:]) != 1 {
		return false, ""
	}

	s.sessionMu.Lock()
	if g.maxClients > 0 && s.active[id] >= g.maxClients {
		s.sessionMu.Unlock()
		return false, ""
	}
	s.active[id]++
	s.sessionMu.Unlock()
	return true, id
}

func (s *Store) Connect(addr net.Addr, id string, tx uint64) {}
func (s *Store) Disconnect(addr net.Addr, id string, err error) {
	if id == "" {
		return
	}
	s.sessionMu.Lock()
	if s.active[id] > 0 {
		s.active[id]--
	}
	s.sessionMu.Unlock()
	if s.OnDisconnect != nil {
		s.OnDisconnect(id)
	}
}
func (s *Store) TCPRequest(addr net.Addr, id, reqAddr string)            {}
func (s *Store) TCPError(addr net.Addr, id, reqAddr string, err error)  {}
func (s *Store) UDPRequest(addr net.Addr, id string, sessionID uint32, reqAddr string) {}
func (s *Store) UDPError(addr net.Addr, id string, sessionID uint32, err error) {}

func (s *Store) LogTraffic(id string, tx, rx uint64) bool {
	if id == "" {
		return true
	}
	st := s.getOrCreateStats(id)
	if tx > 0 {
		st.Tx.Add(tx)
	}
	if rx > 0 {
		st.Rx.Add(rx)
	}
	st.LastSeen.Store(time.Now().Unix())
	return true
}

func (s *Store) LogOnlineState(id string, online bool) {
	if id == "" {
		return
	}
	st := s.getOrCreateStats(id)
	st.Online.Store(online)
	if online {
		st.LastSeen.Store(time.Now().Unix())
	}
}

func (s *Store) TraceStream(stream hcore.HyStream, stats *hcore.StreamStats) {
	if stats != nil {
		st := s.getOrCreateStats(stats.AuthID)
		st.LastSeen.Store(time.Now().Unix())
	}
}

func (s *Store) UntraceStream(stream hcore.HyStream) {}

func (s *Store) getOrCreateStats(id string) *userStats {
	s.statsMu.RLock()
	st, ok := s.stats[id]
	s.statsMu.RUnlock()
	if ok {
		return st
	}
	s.statsMu.Lock()
	defer s.statsMu.Unlock()
	if st, ok := s.stats[id]; ok {
		return st
	}
	st = &userStats{}
	s.stats[id] = st
	return st
}

func (s *Store) UserStats(id string) (tx, rx uint64, online bool) {
	s.statsMu.RLock()
	st, ok := s.stats[id]
	s.statsMu.RUnlock()
	if !ok {
		return 0, 0, false
	}
	return st.Tx.Load(), st.Rx.Load(), st.Online.Load()
}

func (s *Store) AllStats() map[string]struct {
	Tx, Rx  uint64
	Online  bool
	LastSeen int64
} {
	s.statsMu.RLock()
	defer s.statsMu.RUnlock()
	out := make(map[string]struct {
		Tx, Rx    uint64
		Online    bool
		LastSeen  int64
	}, len(s.stats))
	for id, st := range s.stats {
		out[id] = struct {
			Tx, Rx    uint64
			Online    bool
			LastSeen  int64
		}{
			Tx:       st.Tx.Load(),
			Rx:       st.Rx.Load(),
			Online:   st.Online.Load(),
			LastSeen: st.LastSeen.Load(),
		}
	}
	return out
}

func (s *Store) ActiveSessions() map[string]int {
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	out := make(map[string]int, len(s.active))
	for k, v := range s.active {
		if v > 0 {
			out[k] = v
		}
	}
	return out
}

func parseAuth(auth string) (id, secret string, ok bool) {
	idx := strings.IndexByte(auth, ':')
	if idx <= 0 || idx == len(auth)-1 {
		return "", "", false
	}
	return auth[:idx], auth[idx+1:], true
}

func hashSecret(s string) [32]byte {
	return sha256.Sum256([]byte(s))
}
