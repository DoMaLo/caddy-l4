package l4rtsp

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"

	"github.com/mholt/caddy-l4/layer4"
)

func assertNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
}

type testHandler struct{}

func (*testHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.handlers.test_handler_rtsp",
		New: func() caddy.Module { return new(testHandler) },
	}
}

func (h *testHandler) Handle(cx *layer4.Connection, next layer4.Handler) error {
	cx.SetVar("test_handler_called", true)
	if next != nil {
		return next.Handle(cx)
	}
	return nil
}

type cam1Handler struct{}

func (*cam1Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.handlers.rtsp_cam1",
		New: func() caddy.Module { return new(cam1Handler) },
	}
}

func (*cam1Handler) Handle(cx *layer4.Connection, _ layer4.Handler) error {
	cx.SetVar("matched_route", "rtsp_cam1")
	return nil
}

type anyHandler struct{}

func (*anyHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.handlers.rtsp_any",
		New: func() caddy.Module { return new(anyHandler) },
	}
}

func (*anyHandler) Handle(cx *layer4.Connection, _ layer4.Handler) error {
	cx.SetVar("matched_route", "rtsp_any")
	return nil
}

func init() {
	caddy.RegisterModule(&testHandler{})
	caddy.RegisterModule(&cam1Handler{})
	caddy.RegisterModule(&anyHandler{})
}

func rtspMatchTester(t *testing.T, matchers json.RawMessage, data []byte) bool {
	t.Helper()
	in, out := net.Pipe()
	defer func() { _ = in.Close() }()
	defer func() { _ = out.Close() }()

	cx := layer4.WrapConnection(in, make([]byte, 0), zap.NewNop())
	go func() {
		_, err := out.Write(data)
		assertNoError(t, err)
	}()

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	routes := layer4.RouteList{&layer4.Route{
		MatcherSetsRaw: caddyhttp.RawMatcherSets{
			caddy.ModuleMap{"rtsp": matchers},
		},
		HandlersRaw: []json.RawMessage{json.RawMessage(`{"handler":"test_handler_rtsp"}`)},
	}}
	assertNoError(t, routes.Provision(ctx))

	matched := false
	compiledRoute := routes.Compile(zap.NewNop(), 50*time.Millisecond,
		layer4.HandlerFunc(func(con *layer4.Connection) error {
			matched = con.GetVar("test_handler_called") != nil
			return nil
		}))

	assertNoError(t, compiledRoute.Handle(cx))
	return matched
}

func TestMatchRTSP(t *testing.T) {
	reqCam1 := []byte("DESCRIBE rtsp://cam1.example.com/stream RTSP/1.0\r\n" +
		"CSeq: 1\r\n" +
		"Host: cam1.example.com\r\n\r\n")
	reqCam2Host := []byte("OPTIONS * RTSP/1.0\r\n" +
		"CSeq: 1\r\n" +
		"Host: cam2.example.com\r\n\r\n")
	reqHTTP := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	reqRelURI := []byte("PLAY /stream RTSP/1.0\r\nCSeq: 2\r\nHost: cam1.example.com\r\n\r\n")
	// Host header overrides URI authority.
	reqHostOverride := []byte("DESCRIBE rtsp://cam1.example.com/stream RTSP/1.0\r\n" +
		"CSeq: 1\r\n" +
		"Host: cam2.example.com\r\n\r\n")

	tests := []struct {
		name     string
		matchers json.RawMessage
		data     []byte
		want     bool
	}{
		{
			name:     "any-rtsp",
			matchers: json.RawMessage(`{}`),
			data:     reqCam1,
			want:     true,
		},
		{
			name:     "host-from-uri",
			matchers: json.RawMessage(`{"host":["cam1.example.com"]}`),
			data:     reqCam1,
			want:     true,
		},
		{
			name:     "host-from-header",
			matchers: json.RawMessage(`{"host":["cam2.example.com"]}`),
			data:     reqCam2Host,
			want:     true,
		},
		{
			name:     "host-header-overrides-uri",
			matchers: json.RawMessage(`{"host":["cam2.example.com"]}`),
			data:     reqHostOverride,
			want:     true,
		},
		{
			name:     "host-header-overrides-uri-no-match-uri",
			matchers: json.RawMessage(`{"host":["cam1.example.com"]}`),
			data:     reqHostOverride,
			want:     false,
		},
		{
			name:     "host-mismatch",
			matchers: json.RawMessage(`{"host":["cam1.example.com"]}`),
			data:     reqCam2Host,
			want:     false,
		},
		{
			name:     "wildcard-host",
			matchers: json.RawMessage(`{"host":["*.example.com"]}`),
			data:     reqCam1,
			want:     true,
		},
		{
			name:     "relative-uri-with-host-header",
			matchers: json.RawMessage(`{"host":["cam1.example.com"]}`),
			data:     reqRelURI,
			want:     true,
		},
		{
			name:     "not-http",
			matchers: json.RawMessage(`{}`),
			data:     reqHTTP,
			want:     false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := rtspMatchTester(t, tc.matchers, tc.data)
			if got != tc.want {
				t.Fatalf("matched=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestParseRTSPNeedMore(t *testing.T) {
	// Relative URI + incomplete headers: always wait.
	partialRel := []byte("PLAY /stream RTSP/1.0\r\nCSeq: 1\r\n")
	needMore, isRTSP, host := parseRTSP(partialRel)
	if !needMore || !isRTSP || host != "" {
		t.Fatalf("rel: needMore=%v isRTSP=%v host=%q", needMore, isRTSP, host)
	}

	// Absolute URI alone is not enough — Host may still arrive and override.
	absLine := []byte("DESCRIBE rtsp://cam.example.com/s RTSP/1.0\r\n")
	needMore, isRTSP, host = parseRTSP(absLine)
	if !needMore || !isRTSP || host != "" {
		t.Fatalf("abs: needMore=%v isRTSP=%v host=%q", needMore, isRTSP, host)
	}

	// Truncated Host line must not be treated as complete.
	truncHost := []byte("OPTIONS * RTSP/1.0\r\nHost: cam")
	needMore, isRTSP, host = parseRTSP(truncHost)
	if !needMore || !isRTSP || host != "" {
		t.Fatalf("trunc: needMore=%v isRTSP=%v host=%q", needMore, isRTSP, host)
	}
	if h, found := headerValue([]byte("Host: cam"), "host"); found || h != "" {
		t.Fatalf("headerValue on truncated line: found=%v host=%q", found, h)
	}

	// Host overrides URI after headers are complete.
	override := []byte("DESCRIBE rtsp://cam1.example.com/s RTSP/1.0\r\nHost: cam2.example.com\r\n\r\n")
	needMore, isRTSP, host = parseRTSP(override)
	if needMore || !isRTSP || host != "cam2.example.com" {
		t.Fatalf("override: needMore=%v isRTSP=%v host=%q", needMore, isRTSP, host)
	}

	// Incomplete request line.
	needMore, isRTSP, host = parseRTSP([]byte("DESCRIBE rtsp://cam"))
	if !needMore || isRTSP || host != "" {
		t.Fatalf("partial line: needMore=%v isRTSP=%v host=%q", needMore, isRTSP, host)
	}
}

// TestCatchAllWaitsForHostRoutes ensures bare `rtsp` does not steal a connection
// while host-specific routes are still waiting for headers (bug 3).
func TestCatchAllWaitsForHostRoutes(t *testing.T) {
	in, out := net.Pipe()
	defer func() { _ = in.Close() }()
	defer func() { _ = out.Close() }()

	cx := layer4.WrapConnection(in, make([]byte, 0), zap.NewNop())

	// First write only the request line; Host arrives after a short delay so
	// matching must prefetch and wait rather than accepting @any early.
	go func() {
		_, err := out.Write([]byte("OPTIONS * RTSP/1.0\r\n"))
		assertNoError(t, err)
		time.Sleep(20 * time.Millisecond)
		_, err = out.Write([]byte("CSeq: 1\r\nHost: cam1.example.com\r\n\r\n"))
		assertNoError(t, err)
	}()

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	routes := layer4.RouteList{
		&layer4.Route{
			MatcherSetsRaw: caddyhttp.RawMatcherSets{
				caddy.ModuleMap{"rtsp": json.RawMessage(`{"host":["cam1.example.com"]}`)},
			},
			HandlersRaw: []json.RawMessage{json.RawMessage(`{"handler":"rtsp_cam1"}`)},
		},
		&layer4.Route{
			MatcherSetsRaw: caddyhttp.RawMatcherSets{
				caddy.ModuleMap{"rtsp": json.RawMessage(`{}`)},
			},
			HandlersRaw: []json.RawMessage{json.RawMessage(`{"handler":"rtsp_any"}`)},
		},
	}
	assertNoError(t, routes.Provision(ctx))

	compiled := routes.Compile(zap.NewNop(), 200*time.Millisecond,
		layer4.HandlerFunc(func(*layer4.Connection) error { return nil }))
	assertNoError(t, compiled.Handle(cx))

	matched, _ := cx.GetVar("matched_route").(string)
	if matched != "rtsp_cam1" {
		t.Fatalf("matched_route=%q, want rtsp_cam1 (catch-all stole the connection)", matched)
	}
}

func TestUnmarshalCaddyfile(t *testing.T) {
	tests := []struct {
		input string
		hosts []string
	}{
		{`rtsp`, nil},
		{`rtsp host cam1.example.com cam2.example.com`, []string{"cam1.example.com", "cam2.example.com"}},
		{`rtsp {
			host *.example.com
		}`, []string{"*.example.com"}},
	}
	for _, tc := range tests {
		d := caddyfile.NewTestDispenser(tc.input)
		m := &MatchRTSP{}
		assertNoError(t, m.UnmarshalCaddyfile(d))
		if len(m.Host) != len(tc.hosts) {
			t.Fatalf("input %q: got hosts %v, want %v", tc.input, m.Host, tc.hosts)
		}
		for i := range tc.hosts {
			if m.Host[i] != tc.hosts[i] {
				t.Fatalf("input %q: got hosts %v, want %v", tc.input, m.Host, tc.hosts)
			}
		}
	}
}

func TestHostMatches(t *testing.T) {
	m := &MatchRTSP{Host: []string{"Cam.Example.com", "*.labs.local"}}
	if !m.hostMatches("cam.example.com") {
		t.Fatal("exact match failed")
	}
	if !m.hostMatches("cam.example.com:554") {
		t.Fatal("match with port failed")
	}
	if !m.hostMatches("a.labs.local") {
		t.Fatal("wildcard match failed")
	}
	if m.hostMatches("other.com") {
		t.Fatal("unexpected match")
	}
	if m.hostMatches("foo.labs.local.evil") {
		t.Fatal("suffix should not over-match trailing garbage")
	}
}
