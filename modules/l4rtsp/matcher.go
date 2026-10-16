// Copyright 2020 Matthew Holt
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package l4rtsp

import (
	"bytes"
	"net"
	"net/url"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"

	"github.com/mholt/caddy-l4/layer4"
)

func init() {
	caddy.RegisterModule(&MatchRTSP{})
}

// MatchRTSP matches RTSP (over TCP) connections by inspecting the first request.
//
// Matching always waits until the end of the request headers (\r\n\r\n or \n\n)
// before deciding. That way a Host header can override the authority in an
// absolute rtsp:// URI, truncated header lines are not treated as complete, and
// a bare `rtsp` catch-all does not match before host-specific routes that are
// still waiting for more bytes.
//
// With no Host filters configured, any well-formed RTSP request matches.
// With Host filters, the connection matches when the request Host header or
// (if absent) the authority in an absolute rtsp:// URI equals one of the
// configured names (exact or *.suffix wildcards, case-insensitive).
type MatchRTSP struct {
	// Host is a list of hostnames to match. Empty means any RTSP host.
	Host []string `json:"host,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (*MatchRTSP) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.rtsp",
		New: func() caddy.Module { return new(MatchRTSP) },
	}
}

// Match returns true if the connection starts with an RTSP request that
// satisfies the configured host filters.
func (m *MatchRTSP) Match(cx *layer4.Connection) (bool, error) {
	repl := cx.Replacer()
	if host, ok := cx.GetVar(rtspHostVarName).(string); ok {
		return m.hostMatches(host, repl), nil
	}

	data := cx.MatchingBytes()
	needMore, isRTSP, host := parseRTSP(data)
	if needMore {
		if len(data) >= layer4.MaxMatchingBytes {
			return false, layer4.ErrMatchingBufferFull
		}
		return false, layer4.ErrConsumedAllPrefetchedBytes
	}
	if !isRTSP {
		return false, nil
	}

	cx.SetVar(rtspHostVarName, host)
	repl.Set(rtspHostReplKey, host)
	return m.hostMatches(host, repl), nil
}

// hostMatches reports whether host satisfies m.Host. An empty filter matches all.
func (m *MatchRTSP) hostMatches(host string, repl *caddy.Replacer) bool {
	if len(m.Host) == 0 {
		return true
	}
	host = strings.ToLower(stripPort(host))
	if host == "" {
		return false
	}
	for _, pattern := range m.Host {
		if repl != nil {
			pattern = repl.ReplaceAll(pattern, "")
		}
		pattern = strings.ToLower(stripPort(strings.TrimSpace(pattern)))
		if pattern == "" {
			continue
		}
		if strings.HasPrefix(pattern, "*.") {
			suffix := pattern[1:] // ".example.com"
			base := pattern[2:]   // "example.com"
			if host == base || strings.HasSuffix(host, suffix) {
				return true
			}
			continue
		}
		if host == pattern {
			return true
		}
	}
	return false
}

// parseRTSP inspects prefetched bytes.
// needMore is true when more data is required to decide.
func parseRTSP(data []byte) (needMore, isRTSP bool, host string) {
	line, headers, hasNewline := bytes.Cut(data, []byte{'\n'})
	if !hasNewline {
		return looksLikePartialRequestLine(data), false, ""
	}

	if len(line) > 0 && line[len(line)-1] == '\r' {
		line = line[:len(line)-1]
	}

	// Request-Line = Method SP Request-URI SP RTSP-Version
	method, rest, ok := bytes.Cut(line, []byte{' '})
	if !ok || !isValidMethod(method) {
		return false, false, ""
	}
	uri, version, ok := bytes.Cut(rest, []byte{' '})
	if !ok || len(uri) == 0 {
		return false, false, ""
	}
	if !bytes.Equal(version, []byte("RTSP/1.0")) && !bytes.Equal(version, []byte("RTSP/2.0")) {
		return false, false, ""
	}

	// Always wait for the end of headers before a final decision. This lets
	// Host override the URI authority, avoids accepting truncated header lines,
	// and keeps bare `rtsp` catch-alls from matching while host routes prefetch.
	hdrHost, hasHost, complete := parseHeaders(headers)
	if !complete {
		return true, true, ""
	}

	host = hostFromAbsoluteURI(string(uri))
	if hasHost {
		host = hdrHost
	}
	return false, true, host
}

func isMethodChar(b byte) bool {
	// RTSP methods use the HTTP token grammar (tchar).
	return (b >= 'A' && b <= 'Z') ||
		(b >= 'a' && b <= 'z') ||
		(b >= '0' && b <= '9') ||
		strings.ContainsRune("!#$%&'*+-.^_`|~", rune(b))
}

func isValidMethod(method []byte) bool {
	if len(method) == 0 {
		return false
	}
	for _, b := range method {
		if !isMethodChar(b) {
			return false
		}
	}
	return true
}

// looksLikePartialRequestLine reports whether an unterminated first line can
// still become a valid RTSP request line once more bytes arrive.
func looksLikePartialRequestLine(data []byte) bool {
	if len(data) == 0 {
		return true
	}
	for i, b := range data {
		if b == '\r' && i == len(data)-1 {
			continue
		}
		if b < 0x20 || b >= 0x7f {
			return false
		}
	}
	method, rest, hasSpace := bytes.Cut(data, []byte{' '})
	if !isValidMethod(method) {
		return false
	}
	if !hasSpace {
		return true
	}
	uri, version, hasSecondSpace := bytes.Cut(rest, []byte{' '})
	if !hasSecondSpace {
		return true
	}
	if len(uri) == 0 {
		return false
	}
	if len(version) > 0 && version[len(version)-1] == '\r' {
		version = version[:len(version)-1]
	}
	return bytes.HasPrefix([]byte("RTSP/1.0"), version) || bytes.HasPrefix([]byte("RTSP/2.0"), version)
}

func hostFromAbsoluteURI(raw string) string {
	if !strings.Contains(raw, "://") {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Host
}

// parseHeaders scans header lines until the terminating empty line (\r\n or \n).
// Only complete lines (terminated by \n) are considered; a trailing unterminated
// fragment means headers are not yet complete.
func parseHeaders(headers []byte) (host string, hasHost, complete bool) {
	for len(headers) > 0 {
		line, rest, ok := bytes.Cut(headers, []byte{'\n'})
		if !ok {
			// Incomplete trailing line — not a finished header block.
			return "", false, false
		}
		headers = rest
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		if len(line) == 0 {
			// Empty line marks the end of the headers section.
			return host, hasHost, true
		}
		if !hasHost {
			if key, val, hasColon := bytes.Cut(line, []byte{':'}); hasColon {
				if strings.EqualFold(string(bytes.TrimSpace(key)), "host") {
					host = string(bytes.TrimSpace(val))
					hasHost = true
				}
			}
		}
	}
	return "", false, false
}

func stripPort(hostport string) string {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return strings.Trim(hostport, "[]")
	}
	return host
}

// UnmarshalCaddyfile sets up the MatchRTSP from Caddyfile tokens. Syntax:
//
//	rtsp host <names...>
//	rtsp {
//		host <names...>
//	}
//	rtsp
func (m *MatchRTSP) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	_, wrapper := d.Next(), d.Val() // consume wrapper name

	hasInlineArgs := d.NextArg()
	if hasInlineArgs {
		if d.Val() != "host" {
			return d.ArgErr()
		}
		if d.CountRemainingArgs() == 0 {
			return d.ArgErr()
		}
		m.Host = append(m.Host, d.RemainingArgs()...)
	}

	for nesting := d.Nesting(); d.NextBlock(nesting); {
		if hasInlineArgs {
			return d.Errf("malformed %s matcher: cannot combine inline arguments with a block", wrapper)
		}
		optionName := d.Val()
		switch optionName {
		case "host":
			if d.CountRemainingArgs() == 0 {
				return d.ArgErr()
			}
			m.Host = append(m.Host, d.RemainingArgs()...)
		default:
			return d.Errf("unknown %s option '%s'", wrapper, optionName)
		}

		if d.NextBlock(nesting + 1) {
			return d.Errf("malformed %s option '%s': blocks are not supported", wrapper, optionName)
		}
	}

	return nil
}

// Interface guards
var (
	_ layer4.ConnMatcher    = (*MatchRTSP)(nil)
	_ caddyfile.Unmarshaler = (*MatchRTSP)(nil)
)

const (
	rtspReplPrefix  = layer4.AppReplPrefix + "rtsp."
	rtspHostReplKey = rtspReplPrefix + "host"
	rtspHostVarName = "rtsp_host"
)
