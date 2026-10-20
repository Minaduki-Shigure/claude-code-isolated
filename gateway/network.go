package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

var errUpstream = errors.New("upstream unavailable")

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

type gateway struct {
	policy *policy
	proxy  string
	ca     *authorityCA
	roots  *x509.CertPool
	doh    *http.Client
}

func newGateway(p *policy, proxy string) (*gateway, error) {
	a, err := netip.ParseAddrPort(proxy)
	if err != nil || !a.Addr().Is4() || a.Port() == 0 {
		return nil, errors.New("UPSTREAM_PROXY_ADDR must be numeric IPv4:port")
	}
	ca, err := newCA()
	if err != nil {
		return nil, err
	}
	g := &gateway{policy: p, proxy: proxy, ca: ca}
	g.initDNSClient()
	return g, nil
}

// This is the only external socket creation in the gateway. The proxy address
// has already been parsed as numeric IPv4. No system DNS resolver is ever used.
func (g *gateway) proxyTunnel(ctx context.Context, target netip.Addr, port string) (net.Conn, error) {
	if g.policy.checkIP(target) != nil || (port != "80" && port != "443") {
		return nil, errDenied
	}
	d := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	conn, err := d.DialContext(ctx, "tcp4", g.proxy)
	if err != nil {
		return nil, errUpstream
	}
	deadline := time.Now().Add(15 * time.Second)
	if t, ok := ctx.Deadline(); ok && t.Before(deadline) {
		deadline = t
	}
	if err = conn.SetDeadline(deadline); err != nil {
		conn.Close()
		return nil, errUpstream
	}
	targetAuthority := net.JoinHostPort(target.String(), port)
	_, err = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", targetAuthority, targetAuthority)
	if err != nil {
		conn.Close()
		return nil, errUpstream
	}
	// Read only bounded proxy response headers, preserving any tunnel bytes.
	reader := bufio.NewReaderSize(conn, 4096)
	var headers strings.Builder
	for headers.Len() < 16*1024 {
		line, e := reader.ReadSlice('\n')
		if e != nil || len(line)+headers.Len() > 16*1024 {
			conn.Close()
			return nil, errUpstream
		}
		headers.Write(line)
		if string(line) == "\r\n" {
			break
		}
	}
	if !strings.HasSuffix(headers.String(), "\r\n\r\n") {
		conn.Close()
		return nil, errUpstream
	}
	resp, err := http.ReadResponse(bufio.NewReader(strings.NewReader(headers.String())), &http.Request{Method: http.MethodConnect})
	if err != nil || resp.StatusCode != http.StatusOK || len(resp.TransferEncoding) != 0 || resp.ContentLength > 0 {
		conn.Close()
		return nil, errUpstream
	}
	if err = conn.SetDeadline(time.Time{}); err != nil {
		conn.Close()
		return nil, errUpstream
	}
	return &bufferedConn{Conn: conn, reader: reader}, nil
}

func (g *gateway) tlsTo(ctx context.Context, host string, ips []netip.Addr) (net.Conn, error) {
	for _, ip := range ips {
		conn, err := g.proxyTunnel(ctx, ip, "443")
		if err != nil {
			continue
		}
		t := tls.Client(conn, &tls.Config{
			ServerName: host, RootCAs: g.roots, MinVersion: tls.VersionTLS12,
			NextProtos: []string{"http/1.1"},
		})
		handshake, cancel := context.WithTimeout(ctx, 15*time.Second)
		err = t.HandshakeContext(handshake)
		cancel()
		if err == nil {
			return t, nil
		}
		t.Close()
	}
	return nil, errUpstream
}

func (g *gateway) initDNSClient() {
	tr := &http.Transport{
		Proxy: nil, ForceAttemptHTTP2: false, DisableCompression: true,
		MaxIdleConns: 4, MaxIdleConnsPerHost: 2, IdleConnTimeout: 60 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second, MaxResponseHeaderBytes: 16 * 1024,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, errDenied
		},
		DialTLSContext: func(ctx context.Context, _, address string) (net.Conn, error) {
			h, p, err := authority(address, "")
			if err != nil || h != g.policy.DoH.Host || p != "443" {
				return nil, errDenied
			}
			ips := make([]netip.Addr, 0, len(g.policy.DoH.BootstrapIPs))
			for _, s := range g.policy.DoH.BootstrapIPs {
				ips = append(ips, netip.MustParseAddr(s))
			}
			return g.tlsTo(ctx, h, ips)
		},
		TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{},
	}
	g.doh = &http.Client{
		Transport: tr, Timeout: 20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errDenied },
	}
}

type dnsResponse struct {
	Status   int  `json:"Status"`
	TC       bool `json:"TC"`
	Question []struct {
		Name string `json:"name"`
		Type int    `json:"type"`
	} `json:"Question"`
	Answer []struct {
		Name string `json:"name"`
		Type int    `json:"type"`
		Data string `json:"data"`
	} `json:"Answer"`
}

func (g *gateway) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if g.policy.checkHost(host) != nil {
		return nil, errDenied
	}
	ips := make([]netip.Addr, 0, 4)
	seen := map[netip.Addr]bool{}
	// Both families must be validated before selecting an address. An allowed A
	// does not make an official/private AAAA or mixed answer safe.
	for _, typ := range []string{"A", "AAAA"} {
		values := url.Values{"name": {host}, "type": {typ}}
		u := "https://" + g.policy.DoH.Host + g.policy.DoH.Path + "?" + values.Encode()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, errUpstream
		}
		req.Header.Set("Accept", "application/dns-json")
		resp, err := g.doh.Do(req)
		if err != nil {
			return nil, errUpstream
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024+1))
		resp.Body.Close()
		if err != nil || resp.StatusCode != http.StatusOK || len(b) > 64*1024 {
			return nil, errUpstream
		}
		var answer dnsResponse
		if json.Unmarshal(b, &answer) != nil || answer.Status != 0 || answer.TC ||
			len(answer.Answer) > 64 || len(answer.Question) != 1 {
			return nil, errUpstream
		}
		qname, e := canonicalHost(answer.Question[0].Name)
		wantType := 1
		if typ == "AAAA" {
			wantType = 28
		}
		if e != nil || qname != host || answer.Question[0].Type != wantType {
			return nil, errUpstream
		}
		for _, record := range answer.Answer {
			name, e := canonicalHost(record.Name)
			if e != nil || g.policy.checkHost(name) != nil {
				return nil, errDenied
			}
			switch record.Type {
			case 5:
				target, e := canonicalHost(record.Data)
				if e != nil || g.policy.checkHost(target) != nil {
					return nil, errDenied
				}
			case 1, 28:
				a, e := netip.ParseAddr(record.Data)
				if e != nil || g.policy.checkIP(a) != nil ||
					(record.Type == 1 && !a.Is4()) || (record.Type == 28 && !a.Is6()) {
					return nil, errDenied
				}
				if !seen[a] {
					ips = append(ips, a)
					seen[a] = true
				}
			default:
				return nil, errUpstream
			}
		}
	}
	if len(ips) == 0 {
		return nil, errUpstream
	}
	return ips, nil
}

func (g *gateway) transport(host string, port string, ips []netip.Addr) *http.Transport {
	return &http.Transport{
		Proxy: nil, ForceAttemptHTTP2: false,
		MaxIdleConns: 4, MaxIdleConnsPerHost: 4,
		IdleConnTimeout: 60 * time.Second, ResponseHeaderTimeout: 120 * time.Second,
		ExpectContinueTimeout: time.Second, MaxResponseHeaderBytes: 64 * 1024,
		DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
			h, p, err := authority(address, "")
			if err != nil || h != host || p != port || p != "80" {
				return nil, errDenied
			}
			for _, ip := range ips {
				if conn, err := g.proxyTunnel(ctx, ip, port); err == nil {
					return conn, nil
				}
			}
			return nil, errUpstream
		},
		DialTLSContext: func(ctx context.Context, _, address string) (net.Conn, error) {
			h, p, err := authority(address, "")
			if err != nil || h != host || p != port || p != "443" {
				return nil, errDenied
			}
			return g.tlsTo(ctx, host, ips)
		},
		TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{},
	}
}
