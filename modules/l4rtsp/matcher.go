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
// With no Host filters configured, any well-formed RTSP request matches.
// With Host filters, the connection matches when the request Host header or
// the authority in an absolute rtsp:// URI equals one of the configured names
// (exact or *.suffix wildcards, case-insensitive).
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
	if host, ok := cx.GetVar(rtspHostVarName).(string); ok {
		return m.hostMatches(host), nil
	}

	data := cx.MatchingBytes()
	needMore, isRTSP, host := parseRTSP(data, len(m.Host) > 0)
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
	cx.Replacer().Set(rtspHostReplKey, host)
	return m.hostMatches(host), nil
}

// hostMatches reports whether host satisfies m.Host. An empty filter matches all.
func (m *MatchRTSP) hostMatches(host string) bool {
	if len(m.Host) == 0 {
		return true
	}
	host = strings.ToLower(stripPort(host))
	if host == "" {
		return false
	}
	for _, pattern := range m.Host {
		pattern = strings.ToLower(strings.TrimSpace(pattern))
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
func parseRTSP(data []byte, needHost bool) (needMore, isRTSP bool, host string) {
	lineEnd := bytes.IndexByte(data, '\n')
	if lineEnd < 0 {
		return true, false, ""
	}

	line := data[:lineEnd]
	if len(line) > 0 && line[len(line)-1] == '\r' {
		line = line[:len(line)-1]
	}

	// Request-Line = Method SP Request-URI SP RTSP-Version
	method, rest, ok := cutByte(line, ' ')
	if !ok || len(method) == 0 {
		return false, false, ""
	}
	uri, version, ok := cutByte(rest, ' ')
	if !ok {
		return false, false, ""
	}
	if !bytes.HasPrefix(version, []byte("RTSP/")) {
		return false, false, ""
	}
	ver := version[len("RTSP/"):]
	if !bytes.Equal(ver, []byte("1.0")) && !bytes.Equal(ver, []byte("2.0")) {
		return false, false, ""
	}

	isRTSP = true
	host = hostFromAbsoluteURI(string(uri))

	headers := data[lineEnd+1:]
	headersDone := bytes.Contains(headers, []byte("\r\n\r\n")) || bytes.Contains(headers, []byte("\n\n"))
	if h, found := headerValue(headers, "host"); found {
		host = h
	} else if needHost && host == "" && !headersDone {
		// Waiting for Host header (or end of headers proving there is none).
		return true, true, ""
	}

	return false, true, host
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

func headerValue(headers []byte, name string) (string, bool) {
	name = strings.ToLower(name)
	for len(headers) > 0 {
		eol := bytes.IndexByte(headers, '\n')
		var line []byte
		if eol < 0 {
			line = headers
			headers = nil
		} else {
			line = headers[:eol]
			headers = headers[eol+1:]
		}
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		if len(line) == 0 {
			return "", false
		}
		colon := bytes.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		key := strings.ToLower(string(bytes.TrimSpace(line[:colon])))
		if key != name {
			continue
		}
		return string(bytes.TrimSpace(line[colon+1:])), true
	}
	return "", false
}

func cutByte(b []byte, c byte) (before, after []byte, ok bool) {
	i := bytes.IndexByte(b, c)
	if i < 0 {
		return nil, nil, false
	}
	return b[:i], b[i+1:], true
}

func stripPort(hostport string) string {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport
	}
	return host
}

// UnmarshalCaddyfile sets up the MatchRTSP from Caddyfile tokens. Syntax:
//
//	rtsp
//	rtsp host <names...>
//	rtsp {
//		host <names...>
//	}
func (m *MatchRTSP) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	_, wrapper := d.Next(), d.Val() // consume wrapper name

	if d.NextArg() {
		if d.Val() != "host" {
			return d.ArgErr()
		}
		if d.CountRemainingArgs() == 0 {
			return d.ArgErr()
		}
		m.Host = append(m.Host, d.RemainingArgs()...)
	}

	for nesting := d.Nesting(); d.NextBlock(nesting); {
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
