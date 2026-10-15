---
title: RTSP Matcher
---

# RTSP Matcher

## Summary

The RTSP matcher matches connections that start with an [RTSP](https://datatracker.ietf.org/doc/html/rfc2326)
request over TCP. It peeks at the request line (`METHOD <uri> RTSP/1.0|2.0`) and optionally filters by
host name taken from the `Host` header or the authority of an absolute `rtsp://` URI.

When RTSP traffic is detected, the matcher registers the `l4.rtsp.host` placeholder with the resolved host.

## Syntax

### Caddyfile

```caddyfile
# bare `rtsp` matches any RTSP traffic
rtsp

# match RTSP traffic for specific hosts (exact or *.suffix)
rtsp host cam1.example.com *.labs.local

# block form
rtsp {
    host cam1.example.com cam2.example.com
}
```

Example — route cameras by host on TCP port 554:

```caddyfile
{
    layer4 {
        :554 {
            @cam1 rtsp host cam1.example.com
            route @cam1 {
                proxy 10.0.0.10:554
            }

            @cam2 rtsp host cam2.example.com
            route @cam2 {
                proxy 10.0.0.20:554
            }

            # optional catch-all for other RTSP
            @any rtsp
            route @any {
                proxy 10.0.0.99:554
            }
        }
    }
}
```

### JSON

```json
{
    "apps": {
        "layer4": {
            "servers": {
                "rtsp": {
                    "listen": [":554"],
                    "routes": [
                        {
                            "match": [{"rtsp": {"host": ["cam1.example.com"]}}],
                            "handle": [{"handler": "proxy", "upstreams": [{"dial": ["10.0.0.10:554"]}]}]
                        },
                        {
                            "match": [{"rtsp": {}}],
                            "handle": [{"handler": "proxy", "upstreams": [{"dial": ["10.0.0.99:554"]}]}]
                        }
                    ]
                }
            }
        }
    }
}
```

## Notes

- Matching always waits for the end of request headers (`\r\n\r\n` or `\n\n`)
  before deciding. The `Host` header overrides the authority of an absolute
  `rtsp://` URI when both are present. This also keeps a bare `rtsp` catch-all
  from matching while host-specific routes are still prefetching headers.
- Only the first request of the TCP connection is inspected (matching buffer).
- Host matching is case-insensitive; ports in `Host` / URI authority are ignored.
- Wildcard form `*.example.com` matches `example.com` and any subdomain
  (`HasSuffix`); it does not match names like `foo.example.com.bar`.
- Method filtering is not supported; any valid RTSP request line is accepted.
- Interleaved RTP/RTCP over the same TCP connection is proxied after matching; the matcher does not parse media frames.
