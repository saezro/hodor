// Command hodor is the single static binary: it runs the two listeners
// (serve) and offers a small CLI that talks to the admin API (check,
// open, close, status).
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/saezro/hodor/internal/admin"
	"github.com/saezro/hodor/internal/apikey"
	"github.com/saezro/hodor/internal/config"
	"github.com/saezro/hodor/internal/pin"
	"github.com/saezro/hodor/internal/proxy"
	"github.com/saezro/hodor/internal/state"
	"github.com/saezro/hodor/internal/webhook"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = cmdServe(os.Args[2:])
	case "check":
		err = cmdCheck(os.Args[2:])
	case "open":
		err = cmdOpen(os.Args[2:])
	case "close":
		err = cmdClose(os.Args[2:])
	case "status":
		err = cmdStatus(os.Args[2:])
	case "key":
		err = cmdKey(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "hodor:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  hodor serve [-c hodor.yaml]
  hodor check [-c hodor.yaml]
  hodor open <service|group> [-c hodor.yaml] [--for 3h]
  hodor close <service|group> [-c hodor.yaml]
  hodor status [-c hodor.yaml]
  hodor key new [--name N] [--services a,b] [--actions open,close,status]`)
}

// --- key new ---

func cmdKey(args []string) error {
	if len(args) == 0 || args[0] != "new" {
		return errors.New("usage: hodor key new [--name N] [--services a,b] [--actions open,close,status]")
	}
	fs := flag.NewFlagSet("key new", flag.ExitOnError)
	name := fs.String("name", "", "human-readable name for this key (required)")
	services := fs.String("services", "*", "comma-separated service/group names, or * for all")
	actions := fs.String("actions", "open,close,status", "comma-separated subset of open,close,status")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *name == "" {
		return errors.New("--name is required")
	}

	id, err := randomHex(4) // 8 hex chars
	if err != nil {
		return err
	}
	rawKey, hashHex, err := apikey.Generate()
	if err != nil {
		return err
	}

	fmt.Println("key (shown once, store it securely):")
	fmt.Println(" ", rawKey)
	fmt.Println()
	fmt.Println("add under api_keys in hodor.yaml:")
	fmt.Println()
	fmt.Print(keyYAML(id, *name, hashHex, *services, *actions, time.Now().UTC()))
	return nil
}

// keyYAML renders a single api_keys entry as a YAML block. services and
// actions are comma-separated lists; each element is emitted as a quoted
// YAML string so that values like "*" are not parsed as YAML aliases.
func keyYAML(id, name, hashHex, services, actions string, createdAt time.Time) string {
	k := config.APIKey{
		ID:        id,
		Name:      name,
		Hash:      hashHex,
		Services:  splitComma(services),
		Actions:   splitComma(actions),
		CreatedAt: createdAt.Format(time.RFC3339),
	}
	var buf bytes.Buffer
	buf.WriteString("api_keys:\n")
	buf.WriteString("  - id: " + strconv.Quote(k.ID) + "\n")
	buf.WriteString("    name: " + strconv.Quote(k.Name) + "\n")
	buf.WriteString("    hash: " + strconv.Quote(k.Hash) + "\n")
	buf.WriteString("    services: [" + quoteList(k.Services) + "]\n")
	buf.WriteString("    actions: [" + quoteList(k.Actions) + "]\n")
	buf.WriteString("    created_at: " + strconv.Quote(k.CreatedAt) + "\n")
	return buf.String()
}

func splitComma(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func quoteList(items []string) string {
	quoted := make([]string, len(items))
	for i, s := range items {
		quoted[i] = strconv.Quote(s)
	}
	return strings.Join(quoted, ", ")
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// liveKeys returns the state keys and service names currently in c,
// for state.Store.PurgeAbsent and pin.Manager.PurgeAbsent: a state key is
// svc.Group when set (state is shared across a group), else svc.Name.
func liveKeys(c *config.Config) (stateKeys, serviceNames map[string]bool) {
	stateKeys = make(map[string]bool, len(c.Services))
	serviceNames = make(map[string]bool, len(c.Services))
	for _, svc := range c.Services {
		serviceNames[svc.Name] = true
		key := svc.Name
		if svc.Group != "" {
			key = svc.Group
		}
		stateKeys[key] = true
	}
	return stateKeys, serviceNames
}

func configPath(fs *flag.FlagSet) *string {
	def := os.Getenv("HODOR_CONFIG")
	if def == "" {
		def = "hodor.yaml"
	}
	return fs.String("c", def, "path to hodor.yaml")
}

// --- serve ---

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	path := configPath(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	slog.SetDefault(logger)

	live, err := config.NewLive(*path)
	if err != nil {
		return err
	}
	cfg := live.Get()
	secret, err := cfg.Secret()
	if err != nil {
		return fmt.Errorf("secret: %w", err)
	}

	names := make([]string, 0, len(cfg.Services))
	for _, s := range cfg.Services {
		names = append(names, s.Name)
	}
	st, err := state.New(cfg.StateFile, names, nil)
	if err != nil {
		return fmt.Errorf("state: %w", err)
	}

	// State is persisted to disk, so a service deleted from the yaml
	// while hodor was stopped would otherwise have its stale open/expiry
	// state and device passes loaded right back in on this startup; purge
	// it against the config we just read before anything else touches st.
	stateKeys, serviceNames := liveKeys(cfg)
	if err := st.PurgeAbsent(stateKeys, serviceNames); err != nil {
		return fmt.Errorf("state: purge: %w", err)
	}

	st.SetOnChange(webhook.Notifier(cfg.OnChange, logger))
	st.StartAutoClose(time.Minute)
	defer st.Stop()

	pins := pin.New(nil)

	// A service that disappears from the live config (DeleteService, or
	// a reload/save whose new config just drops it) must lose its
	// open/expiry state and its device passes: otherwise a later
	// service recreated under the same name would inherit whatever
	// in-memory+persisted state the old one left behind instead of
	// starting closed and pass-less.
	live.OnSwap(func(_, next *config.Config) {
		stateKeys, serviceNames := liveKeys(next)
		if err := st.PurgeAbsent(stateKeys, serviceNames); err != nil {
			logger.Error("state: purge absent services failed", "err", err)
		}
		pins.PurgeAbsent(serviceNames)
	})

	publicSrv, err := proxy.New(live, st, pins, secret, logger)
	if err != nil {
		return fmt.Errorf("proxy: %w", err)
	}
	adminSrv, err := admin.New(live, st, pins, secret, logger)
	if err != nil {
		return fmt.Errorf("admin: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// SIGHUP re-reads base + overlay from disk (same as POST
	// /api/config/reload); listen/secret_file/state_file stay as they
	// are, with a warning, since the listeners/secret/state store
	// below are already running against the old values (see
	// internal/config.Live.Reload).
	sighup := make(chan os.Signal, 1)
	signal.Notify(sighup, syscall.SIGHUP)
	defer signal.Stop(sighup)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-sighup:
				warnings, err := live.Reload()
				if err != nil {
					logger.Error("config reload failed", "err", err)
					continue
				}
				for _, w := range warnings {
					logger.Warn("config reload warning", "warning", w)
				}
				logger.Info("config reloaded")
			}
		}
	}()

	httpPublic := &http.Server{Addr: cfg.Listen.Public, Handler: publicSrv, ReadHeaderTimeout: 10 * time.Second}
	httpAdmin := &http.Server{Addr: cfg.Listen.Admin, Handler: adminSrv, ReadHeaderTimeout: 10 * time.Second}

	errc := make(chan error, 2)
	go func() {
		logger.Info("public listener starting", "addr", cfg.Listen.Public)
		if err := httpPublic.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- fmt.Errorf("public listener: %w", err)
		}
	}()
	go func() {
		logger.Info("admin listener starting", "addr", cfg.Listen.Admin)
		if err := httpAdmin.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- fmt.Errorf("admin listener: %w", err)
		}
	}()

	select {
	case <-ctx.Done():
		logger.Info("shutting down")
	case err := <-errc:
		logger.Error("listener failed", "err", err)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpPublic.Shutdown(shutdownCtx); err != nil {
		logger.Error("public listener shutdown failed", "err", err)
	}
	if err := httpAdmin.Shutdown(shutdownCtx); err != nil {
		logger.Error("admin listener shutdown failed", "err", err)
	}
	return nil
}

// --- check ---

func cmdCheck(args []string) error {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	path := configPath(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if _, err := config.Load(*path); err != nil {
		return err
	}
	fmt.Println("config OK:", *path)
	return nil
}

// --- CLI -> admin API client ---

func adminBaseURL(cfg *config.Config) string {
	addr := cfg.Listen.Admin
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	scheme := "http"
	return scheme + "://" + addr
}

func adminRequest(cfg *config.Config, method, path string, body any) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, adminBaseURL(cfg)+path, reader)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	token := cfg.Admin.Token
	if token == "" {
		var err error
		token, err = readSetupToken(cfg)
		if err != nil {
			return nil, err
		}
	}
	req.Header.Set("Authorization", "Bearer "+token)
	client := &http.Client{Timeout: 10 * time.Second}
	return client.Do(req)
}

// setupTokenPath mirrors internal/admin.setupTokenPath: the setup token
// file lives next to state_file, which is itself already defaulted to
// the zero-file-setup data dir (HODOR_DATA_DIR, or /data).
func setupTokenPath(cfg *config.Config) string {
	return filepath.Join(filepath.Dir(cfg.StateFile), "setup.token")
}

// readSetupToken reads the setup token written by the admin server when
// no admin.token is configured (see internal/admin.New), so the CLI
// (e.g. `docker exec hodor hodor open x`) can authenticate without one.
func readSetupToken(cfg *config.Config) (string, error) {
	path := setupTokenPath(cfg)
	b, err := os.ReadFile(path) // #nosec G304 -- path derived from operator config (data dir)
	if err != nil {
		return "", fmt.Errorf("no admin token configured and %s not readable: set admin.token or run where the data dir is accessible", path)
	}
	return strings.TrimSpace(string(b)), nil
}

func cmdOpen(args []string) error {
	fs := flag.NewFlagSet("open", flag.ExitOnError)
	path := configPath(fs)
	forDur := fs.String("for", "", "duration to open for, e.g. 3h (default: until closed)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) != 1 {
		return errors.New("usage: hodor open <service|group> [--for 3h]")
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	resp, err := adminRequest(cfg, http.MethodPost, "/api/services/"+url.PathEscape(rest[0])+"/open", admin.OpenRequest{For: *forDur})
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		return apiError(resp)
	}
	fmt.Println("opened", rest[0])
	return nil
}

func cmdClose(args []string) error {
	fs := flag.NewFlagSet("close", flag.ExitOnError)
	path := configPath(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) != 1 {
		return errors.New("usage: hodor close <service|group>")
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	resp, err := adminRequest(cfg, http.MethodPost, "/api/services/"+url.PathEscape(rest[0])+"/close", nil)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		return apiError(resp)
	}
	fmt.Println("closed", rest[0])
	return nil
}

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	path := configPath(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	resp, err := adminRequest(cfg, http.MethodGet, "/api/services", nil)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		return apiError(resp)
	}
	var services []admin.ServiceView
	if err := json.NewDecoder(resp.Body).Decode(&services); err != nil {
		return err
	}
	for _, s := range services {
		state := "closed"
		if s.Open {
			state = "open"
		}
		until := ""
		if s.Until != nil {
			until = " until " + s.Until.Local().Format(time.RFC3339)
		}
		fmt.Printf("%-20s %-6s %s%s\n", s.Name, state, s.Mode, until)
	}
	return nil
}

func apiError(resp *http.Response) error {
	var e struct {
		Error string `json:"error"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&e)
	if e.Error == "" {
		e.Error = resp.Status
	}
	return fmt.Errorf("admin api: %s", e.Error)
}
