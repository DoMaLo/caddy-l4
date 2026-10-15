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
	return next.Handle(cx)
}

func init() {
	caddy.RegisterModule(&testHandler{})
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
	// Relative URI + incomplete headers: wait for Host.
	partialRel := []byte("PLAY /stream RTSP/1.0\r\nCSeq: 1\r\n")
	needMore, isRTSP, host := parseRTSP(partialRel, true)
	if !needMore || !isRTSP || host != "" {
		t.Fatalf("rel: needMore=%v isRTSP=%v host=%q", needMore, isRTSP, host)
	}

	// Absolute URI already carries the host — no need to wait for Host header.
	absLine := []byte("DESCRIBE rtsp://cam.example.com/s RTSP/1.0\r\n")
	needMore, isRTSP, host = parseRTSP(absLine, true)
	if needMore || !isRTSP || host != "cam.example.com" {
		t.Fatalf("abs: needMore=%v isRTSP=%v host=%q", needMore, isRTSP, host)
	}

	// Incomplete request line.
	needMore, isRTSP, host = parseRTSP([]byte("DESCRIBE rtsp://cam"), true)
	if !needMore || isRTSP || host != "" {
		t.Fatalf("partial line: needMore=%v isRTSP=%v host=%q", needMore, isRTSP, host)
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
}
