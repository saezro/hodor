package config

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// writeBase writes a minimal valid base hodor.yaml with its
// config_overlay pointed at overlayPath, under dir, returning the base
// path.
func writeBase(t *testing.T, dir, overlayPath string) string {
	t.Helper()
	basePath := filepath.Join(dir, "hodor.yaml")
	data := "state_file: " + filepath.Join(dir, "state.json") + "\n" +
		"config_overlay: " + overlayPath + "\n" +
		"services:\n" +
		"  - name: svc1\n" +
		"    hosts: [svc1.example.com]\n" +
		"    mode: proxy\n" +
		"    upstream: http://127.0.0.1:9001\n"
	if err := os.WriteFile(basePath, []byte(data), 0o600); err != nil {
		t.Fatalf("write base: %v", err)
	}
	return basePath
}

func TestLive_SaveInvalid_LeavesOverlayAndConfigUntouched(t *testing.T) {
	dir := t.TempDir()
	overlayPath := filepath.Join(dir, "managed.yaml")
	basePath := writeBase(t, dir, overlayPath)

	live, err := NewLive(basePath)
	if err != nil {
		t.Fatalf("NewLive: %v", err)
	}

	// Seed the overlay with one valid service first, so there is
	// something on disk to compare against byte-for-byte.
	if _, err := live.PutService(Service{Name: "ok", Hosts: []string{"ok.example.com"}, Mode: ModeProxy, Upstream: "http://127.0.0.1:9002"}); err != nil {
		t.Fatalf("seed PutService: %v", err)
	}
	before, err := os.ReadFile(overlayPath)
	if err != nil {
		t.Fatalf("read overlay after seed: %v", err)
	}
	cfgBefore := live.Get()

	// Invalid: no hosts, proxy mode with no upstream -> Validate fails.
	if _, err := live.PutService(Service{Name: "bad", Hosts: []string{"ok.example.com"}, Mode: ModeProxy}); err == nil {
		t.Fatalf("PutService with invalid service: want error, got nil")
	}

	after, err := os.ReadFile(overlayPath)
	if err != nil {
		t.Fatalf("read overlay after failed save: %v", err)
	}
	if string(before) != string(after) {
		t.Errorf("overlay file changed after a rejected save:\nbefore:\n%s\nafter:\n%s", before, after)
	}
	if live.Get() != cfgBefore {
		t.Errorf("Live.Get() changed after a rejected save")
	}
}

func TestLive_PutService_InvalidUpstream_RejectedAndOverlayIntact(t *testing.T) {
	dir := t.TempDir()
	overlayPath := filepath.Join(dir, "managed.yaml")
	basePath := writeBase(t, dir, overlayPath)

	live, err := NewLive(basePath)
	if err != nil {
		t.Fatalf("NewLive: %v", err)
	}
	if _, err := live.PutService(Service{Name: "ok", Hosts: []string{"ok.example.com"}, Mode: ModeProxy, Upstream: "http://127.0.0.1:9002"}); err != nil {
		t.Fatalf("seed PutService: %v", err)
	}
	before, err := os.ReadFile(overlayPath)
	if err != nil {
		t.Fatalf("read overlay after seed: %v", err)
	}
	cfgBefore := live.Get()

	if _, err := live.PutService(Service{Name: "bad", Hosts: []string{"bad.example.com"}, Mode: ModeProxy, Upstream: "not-a-url-%"}); err == nil {
		t.Fatalf("PutService with invalid upstream: want error, got nil")
	}

	after, err := os.ReadFile(overlayPath)
	if err != nil {
		t.Fatalf("read overlay after rejected save: %v", err)
	}
	if string(before) != string(after) {
		t.Errorf("overlay file changed after a rejected save:\nbefore:\n%s\nafter:\n%s", before, after)
	}
	if live.Get() != cfgBefore {
		t.Errorf("Live.Get() changed after a rejected save")
	}
}

func TestLive_AddAPIKey_CollisionRejected(t *testing.T) {
	dir := t.TempDir()
	overlayPath := filepath.Join(dir, "managed.yaml")
	basePath := writeBase(t, dir, overlayPath)

	live, err := NewLive(basePath)
	if err != nil {
		t.Fatalf("NewLive: %v", err)
	}
	k := APIKey{Name: "n1", Hash: strVal(64, 'a'), Services: []string{"svc1"}, Actions: []string{KeyActionStatus}}
	if _, err := live.AddAPIKey("dup1", k); err != nil {
		t.Fatalf("first AddAPIKey: %v", err)
	}
	if _, err := live.AddAPIKey("dup1", k); err == nil {
		t.Fatalf("second AddAPIKey with same id: want error, got nil")
	}
}

func TestLive_ReloadConcurrentWithGet(t *testing.T) {
	dir := t.TempDir()
	overlayPath := filepath.Join(dir, "managed.yaml")
	basePath := writeBase(t, dir, overlayPath)

	live, err := NewLive(basePath)
	if err != nil {
		t.Fatalf("NewLive: %v", err)
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Readers: just hammer Get() concurrently with the writer below.
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = live.Get()
				}
			}
		}()
	}

	for i := 0; i < 20; i++ {
		if _, err := live.Reload(); err != nil {
			t.Errorf("Reload: %v", err)
		}
	}
	close(stop)
	wg.Wait()
}

func TestLive_Reload_ListenChanged_WarnsAndKeepsOld(t *testing.T) {
	dir := t.TempDir()
	overlayPath := filepath.Join(dir, "managed.yaml")
	basePath := writeBase(t, dir, overlayPath)

	live, err := NewLive(basePath)
	if err != nil {
		t.Fatalf("NewLive: %v", err)
	}
	oldListen := live.Get().Listen

	// Rewrite base on disk with a different listen.public.
	data := "state_file: " + filepath.Join(dir, "state.json") + "\n" +
		"config_overlay: " + overlayPath + "\n" +
		"listen: { public: \":9999\" }\n" +
		"services:\n" +
		"  - name: svc1\n" +
		"    hosts: [svc1.example.com]\n" +
		"    mode: proxy\n" +
		"    upstream: http://127.0.0.1:9001\n"
	if err := os.WriteFile(basePath, []byte(data), 0o600); err != nil {
		t.Fatalf("rewrite base: %v", err)
	}

	warnings, err := live.Reload()
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if len(warnings) == 0 {
		t.Fatalf("Reload with changed listen: want a warning, got none")
	}
	if live.Get().Listen != oldListen {
		t.Errorf("Listen after reload = %+v, want unchanged %+v", live.Get().Listen, oldListen)
	}
}

func TestLive_MissingOverlay_EqualsBaseAlone(t *testing.T) {
	dir := t.TempDir()
	overlayPath := filepath.Join(dir, "managed.yaml") // never written
	basePath := writeBase(t, dir, overlayPath)

	live, err := NewLive(basePath)
	if err != nil {
		t.Fatalf("NewLive: %v", err)
	}
	if _, err := os.Stat(overlayPath); !os.IsNotExist(err) {
		t.Fatalf("overlay unexpectedly exists: %v", err)
	}

	base, err := Load(basePath)
	if err != nil {
		t.Fatalf("Load base: %v", err)
	}

	merged := live.Get()
	if len(merged.Services) != len(base.Services) || merged.Services[0].Name != base.Services[0].Name {
		t.Errorf("merged services = %+v, want base alone %+v", merged.Services, base.Services)
	}
	if merged.Services[0].Source != "base" {
		t.Errorf("merged service Source = %q, want %q", merged.Services[0].Source, "base")
	}
}
