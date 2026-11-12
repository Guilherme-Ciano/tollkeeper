package upstream

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/Guilherme-Ciano/tollkeeper/internal/config"
)

var ErrUnknownTransport = errors.New("unknown transport")

func Factory(
	ctx context.Context,
	cfg config.Upstream,
	log *slog.Logger,
	environ func(string) (string, bool),
) (TransportFactory, error) {
	switch cfg.Transport {
	case config.TransportStdio:
		return stdioFactory(cfg, log, environ), nil
	case config.TransportStreamable:
		hc, err := HTTPClient(ctx, cfg)
		if err != nil {
			return nil, err
		}
		return func(context.Context) (mcp.Transport, func(), error) {
			return &mcp.StreamableClientTransport{
				Endpoint:             cfg.URL,
				HTTPClient:           hc,
				DisableStandaloneSSE: true,
			}, func() {}, nil
		}, nil
	default:
		return nil, fmt.Errorf("%s: %w %q", cfg.ID, ErrUnknownTransport, cfg.Transport)
	}
}

func StdioEnv(cfg config.Upstream, environ func(string) (string, bool)) []string {
	env := make([]string, 0, len(cfg.Env)+len(cfg.EnvPassthrough)+1)
	seen := map[string]bool{}
	for _, name := range cfg.EnvPassthrough {
		if v, ok := environ(name); ok && !seen[name] {
			env = append(env, name+"="+v)
			seen[name] = true
		}
	}
	keys := make([]string, 0, len(cfg.Env))
	for k := range cfg.Env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		env = append(env, k+"="+cfg.Env[k])
		seen[k] = true
	}
	if !seen["PATH"] {
		env = append(env, "PATH=/usr/local/bin:/usr/bin:/bin")
	}
	return env
}

func stdioFactory(cfg config.Upstream, log *slog.Logger, environ func(string) (string, bool)) TransportFactory {
	return func(ctx context.Context) (mcp.Transport, func(), error) {
		cmd := exec.CommandContext(ctx, cfg.Command[0], cfg.Command[1:]...)
		cmd.Env = StdioEnv(cfg, environ)
		cmd.SysProcAttr = processGroup()
		stderr, err := cmd.StderrPipe()
		if err != nil {
			return nil, nil, fmt.Errorf("stderr pipe %s: %w", cfg.ID, err)
		}
		go pipeLog(stderr, log.With(slog.String("upstream", cfg.ID), slog.String("stream", "stderr")))
		cleanup := func() {
			if cmd.Process != nil {
				if err := killGroup(cmd.Process.Pid); err != nil {
					log.WarnContext(
						ctx,
						"stdio cleanup failed",
						slog.String("upstream", cfg.ID),
						slog.String("error", err.Error()),
					)
				}
			}
		}
		return &mcp.CommandTransport{Command: cmd, TerminateDuration: 2 * time.Second}, cleanup, nil
	}
}

func pipeLog(r io.Reader, log *slog.Logger) {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 4096), 64<<10)
	for s.Scan() {
		log.Info("upstream stderr", slog.String("line", s.Text()))
	}
}

type bearerTransport struct {
	token string
	base  http.RoundTripper
}

func (b bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r2 := r.Clone(r.Context())
	r2.Header.Set("Authorization", "Bearer "+b.token)
	resp, err := b.base.RoundTrip(r2)
	if err != nil {
		return nil, fmt.Errorf("upstream request: %w", err)
	}
	return resp, nil
}

func baseTransport() *http.Transport {
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		MaxIdleConns:          256,
		MaxIdleConnsPerHost:   256,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 0,
		ForceAttemptHTTP2:     true,
	}
}

func HTTPClient(ctx context.Context, cfg config.Upstream) (*http.Client, error) {
	var rt http.RoundTripper = otelhttp.NewTransport(baseTransport())
	switch cfg.Auth.Type {
	case config.UpstreamAuthBearer:
		rt = bearerTransport{token: cfg.Auth.Token, base: rt}
	case config.UpstreamAuthClientCredentials:
		params := url.Values{}
		if cfg.Auth.Resource != "" {
			params.Set("resource", cfg.Auth.Resource)
		}
		cc := &clientcredentials.Config{
			ClientID:       cfg.Auth.ClientID,
			ClientSecret:   cfg.Auth.ClientSecret,
			TokenURL:       cfg.Auth.TokenURL,
			Scopes:         cfg.Auth.Scopes,
			EndpointParams: params,
			AuthStyle:      oauth2.AuthStyleInHeader,
		}
		tokenClient := &http.Client{Transport: otelhttp.NewTransport(baseTransport()), Timeout: 10 * time.Second}
		tctx := context.WithValue(context.WithoutCancel(ctx), oauth2.HTTPClient, tokenClient)
		rt = &oauth2.Transport{Source: oauth2.ReuseTokenSource(nil, cc.TokenSource(tctx)), Base: rt}
	case config.UpstreamAuthNone, "":
	default:
		return nil, fmt.Errorf("%s: unknown upstream auth %q: %w", cfg.ID, cfg.Auth.Type, ErrUnknownTransport)
	}
	return &http.Client{Transport: rt}, nil
}

func LookupEnv(name string) (string, bool) {
	return os.LookupEnv(name)
}
