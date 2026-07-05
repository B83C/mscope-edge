package auth

import (
	"net"
	"sync"
	"testing"
	"time"

	"mscope-hysteria/pkg/control"
)

func testGrant(id, secret string) control.UserGrant {
	return control.UserGrant{
		UserID:     id,
		Secret:     secret,
		MaxClients: 3,
		ExpiresAt:  time.Now().Add(24 * time.Hour),
	}
}

func TestAuthenticate_Success(t *testing.T) {
	s := NewStore()
	s.Apply(control.GrantsPayload{Grants: []control.UserGrant{testGrant("alice", "secret")}})

	ok, id := s.Authenticate(&net.TCPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 12345}, "alice:secret", 0)
	if !ok {
		t.Fatal("expected auth to pass")
	}
	if id != "alice" {
		t.Errorf("got id=%q, want %q", id, "alice")
	}
}

func TestAuthenticate_WrongSecret(t *testing.T) {
	s := NewStore()
	s.Apply(control.GrantsPayload{Grants: []control.UserGrant{testGrant("alice", "correct")}})

	ok, _ := s.Authenticate(&net.TCPAddr{}, "alice:wrong", 0)
	if ok {
		t.Error("expected auth to fail with wrong secret")
	}
}

func TestAuthenticate_UnknownUser(t *testing.T) {
	s := NewStore()
	s.Apply(control.GrantsPayload{Grants: []control.UserGrant{testGrant("alice", "x")}})

	ok, _ := s.Authenticate(&net.TCPAddr{}, "bob:x", 0)
	if ok {
		t.Error("expected auth to fail for unknown user")
	}
}

func TestAuthenticate_BadFormat(t *testing.T) {
	s := NewStore()
	s.Apply(control.GrantsPayload{Grants: []control.UserGrant{testGrant("alice", "x")}})

	tests := []string{"", ":", "nocolon", ":x", "x:"}
	for _, tc := range tests {
		ok, _ := s.Authenticate(&net.TCPAddr{}, tc, 0)
		if ok {
			t.Errorf("expected auth to fail for %q", tc)
		}
	}
}

func TestAuthenticate_Expired(t *testing.T) {
	s := NewStore()
	s.Apply(control.GrantsPayload{Grants: []control.UserGrant{
		{UserID: "alice", Secret: "x", MaxClients: 1, ExpiresAt: time.Now().Add(-1 * time.Hour)},
	}})

	ok, _ := s.Authenticate(&net.TCPAddr{}, "alice:x", 0)
	if ok {
		t.Error("expected auth to fail for expired grant")
	}
}

func TestMaxClients_Exceeded(t *testing.T) {
	s := NewStore()
	s.Apply(control.GrantsPayload{Grants: []control.UserGrant{
		{UserID: "bob", Secret: "x", MaxClients: 1, ExpiresAt: time.Now().Add(24 * time.Hour)},
	}})

	// First auth passes
	ok1, _ := s.Authenticate(&net.TCPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 100}, "bob:x", 0)
	if !ok1 {
		t.Fatal("first auth should pass")
	}

	// Second auth from same user should fail (max_clients=1)
	ok2, _ := s.Authenticate(&net.TCPAddr{IP: net.IPv4(2, 2, 2, 2), Port: 200}, "bob:x", 0)
	if ok2 {
		t.Error("second auth should fail (max_clients=1)")
	}
}

func TestMaxClients_DisconnectReleasesSlot(t *testing.T) {
	s := NewStore()
	s.Apply(control.GrantsPayload{Grants: []control.UserGrant{
		{UserID: "carol", Secret: "x", MaxClients: 1, ExpiresAt: time.Now().Add(24 * time.Hour)},
	}})

	ok1, _ := s.Authenticate(&net.TCPAddr{}, "carol:x", 0)
	if !ok1 {
		t.Fatal("first auth should pass")
	}

	s.Disconnect(nil, "carol", nil)

	ok2, _ := s.Authenticate(&net.TCPAddr{}, "carol:x", 0)
	if !ok2 {
		t.Error("auth should pass after disconnect frees slot")
	}
}

func TestRevoke(t *testing.T) {
	s := NewStore()
	s.Apply(control.GrantsPayload{Grants: []control.UserGrant{testGrant("alice", "x")}})

	s.Revoke(control.RevokePayload{Users: []string{"alice"}})

	ok, _ := s.Authenticate(&net.TCPAddr{}, "alice:x", 0)
	if ok {
		t.Error("expected auth to fail after revoke")
	}
}

func TestTrafficLogger(t *testing.T) {
	s := NewStore()
	s.Apply(control.GrantsPayload{Grants: []control.UserGrant{testGrant("alice", "x")}})

	s.LogTraffic("alice", 100, 200)
	s.LogTraffic("alice", 50, 75)

	tx, rx, online := s.UserStats("alice")
	if tx != 150 {
		t.Errorf("expected tx=150, got %d", tx)
	}
	if rx != 275 {
		t.Errorf("expected rx=275, got %d", rx)
	}
	if online {
		t.Error("expected offline by default")
	}
}

func TestTrafficLogger_OnlineState(t *testing.T) {
	s := NewStore()
	s.LogOnlineState("bob", true)

	_, _, online := s.UserStats("bob")
	if !online {
		t.Error("expected online after LogOnlineState(true)")
	}

	s.LogOnlineState("bob", false)
	_, _, online = s.UserStats("bob")
	if online {
		t.Error("expected offline after LogOnlineState(false)")
	}
}

func TestConcurrentAuth(t *testing.T) {
	s := NewStore()
	s.Apply(control.GrantsPayload{Grants: []control.UserGrant{testGrant("alice", "x")}})

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				s.Authenticate(&net.TCPAddr{}, "alice:x", 0)
				s.LogTraffic("alice", 1, 1)
				s.Disconnect(nil, "alice", nil)
			}
		}()
	}
	wg.Wait()

	tx, rx, _ := s.UserStats("alice")
	_ = tx
	_ = rx
}

func TestParseAuth(t *testing.T) {
	tests := []struct {
		input      string
		wantID     string
		wantSecret string
		wantOK     bool
	}{
		{"alice:secret", "alice", "secret", true},
		{"complex:with:colons", "complex", "with:colons", true},
		{"onlyid", "", "", false},
		{":x", "", "", false},
		{"x:", "", "", false},
		{"", "", "", false},
	}
	for _, tc := range tests {
		id, secret, ok := parseAuth(tc.input)
		if ok != tc.wantOK {
			t.Errorf("parseAuth(%q) ok=%v, want %v", tc.input, ok, tc.wantOK)
			continue
		}
		if id != tc.wantID || secret != tc.wantSecret {
			t.Errorf("parseAuth(%q) = (%q,%q), want (%q,%q)", tc.input, id, secret, tc.wantID, tc.wantSecret)
		}
	}
}

func TestApplyGrants_ExpiresExisting(t *testing.T) {
	s := NewStore()
	s.Apply(control.GrantsPayload{Grants: []control.UserGrant{
		{UserID: "old", Secret: "x", MaxClients: 1, ExpiresAt: time.Now().Add(-1 * time.Hour)},
	}})

	s.Apply(control.GrantsPayload{Grants: []control.UserGrant{
		{UserID: "new", Secret: "y", MaxClients: 1, ExpiresAt: time.Now().Add(24 * time.Hour)},
	}})

	_, foundOld := s.grants["old"]
	if foundOld {
		t.Error("expected expired grant to be removed")
	}
	_, foundNew := s.grants["new"]
	if !foundNew {
		t.Error("expected new grant to exist")
	}
}

func TestActiveSessions(t *testing.T) {
	s := NewStore()
	s.Apply(control.GrantsPayload{Grants: []control.UserGrant{testGrant("alice", "x")}})

	s.Authenticate(&net.TCPAddr{}, "alice:x", 0)
	s.Authenticate(&net.TCPAddr{}, "alice:x", 0)
	s.Authenticate(&net.TCPAddr{}, "alice:x", 0)

	active := s.ActiveSessions()
	if active["alice"] != 3 {
		t.Errorf("expected 3 active sessions, got %d", active["alice"])
	}

	s.Disconnect(nil, "alice", nil)
	active = s.ActiveSessions()
	if active["alice"] != 2 {
		t.Errorf("expected 2 active after disconnect, got %d", active["alice"])
	}
}
