package configsource

import (
	"testing"

	"github.com/B83C/mscope-edge/pkg/control"
)

func TestApplyConfig(t *testing.T) {
	s := New()
	_, ok := s.Current()
	if ok {
		t.Error("Current should return false before any config")
	}

	cfg := control.ConfigPayload{
		Config: control.ServerConfig{
			Listen:  "0.0.0.0:443",
			CertSNI: "test.example.com",
			TCPMbps: 200,
		},
	}

	if err := s.Apply(cfg); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	got, ok := s.Current()
	if !ok {
		t.Fatal("Current should return true after apply")
	}
	if got.Config.TCPMbps != 200 {
		t.Errorf("got TCPMbps=%d, want 200", got.Config.TCPMbps)
	}
	if got.Config.Listen != "0.0.0.0:443" {
		t.Errorf("got Listen=%q, want %q", got.Config.Listen, "0.0.0.0:443")
	}
}

func TestApplyReplacesOldConfig(t *testing.T) {
	s := New()
	s.Apply(control.ConfigPayload{Config: control.ServerConfig{TCPMbps: 100}})
	s.Apply(control.ConfigPayload{Config: control.ServerConfig{TCPMbps: 200}})

	got, _ := s.Current()
	if got.Config.TCPMbps != 200 {
		t.Errorf("got TCPMbps=%d, want 200", got.Config.TCPMbps)
	}
}

func TestConfigConcurrency(t *testing.T) {
	s := New()
	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			s.Apply(control.ConfigPayload{Config: control.ServerConfig{TCPMbps: i}})
		}
		close(done)
	}()
	for i := 0; i < 100; i++ {
		s.Current()
	}
	<-done
}
