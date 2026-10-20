package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func testPolicy(t *testing.T) *policy {
	t.Helper()
	p, err := loadPolicy("policy.json")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDestinationPolicy(t *testing.T) {
	p := testPolicy(t)
	for _, host := range []string{
		"api.anthropic.com", "API.ANTHROPIC.COM.", "claude.ai",
		"x.claudemcpcontent.com", "http-intake.logs.us5.datadoghq.com",
		"browser-intake-us5-datadoghq.com", "o123.ingest.sentry.io",
		"127.0.0.1", "2130706433", "0177.0.0.1", "0x7f000001",
		"foo.local", "host.docker.internal", "foo.invalid", "foo.onion",
		"api.anthropic.com..", "api.anthropic.com@allowed.com",
	} {
		if p.checkHost(host) == nil {
			t.Errorf("accepted forbidden host %q", host)
		}
	}
	for _, host := range []string{"example.com", "api.github.com", "anthropic.com.example.com", "xn--bcher-kva.de"} {
		if p.checkHost(host) != nil {
			t.Errorf("rejected allowed host %q", host)
		}
	}
	for _, ip := range []string{
		"127.0.0.1", "10.0.0.1", "172.31.0.1", "192.168.0.1",
		"100.100.100.200", "169.254.169.254", "192.0.2.1", "224.0.0.1",
		"160.79.104.1", "160.79.111.255", "::1", "::ffff:93.184.216.34",
		"fc00::1", "fe80::1", "2001:db8::1", "2002:7f00:1::", "2607:6bc0::1",
	} {
		if p.checkIP(netip.MustParseAddr(ip)) == nil {
			t.Errorf("accepted forbidden IP %q", ip)
		}
	}
	for _, ip := range []string{"93.184.216.34", "1.1.1.1", "2606:4700:4700::1111"} {
		if p.checkIP(netip.MustParseAddr(ip)) != nil {
			t.Errorf("rejected public IP %q", ip)
		}
	}
}

func TestOfficialSharedHostPaths(t *testing.T) {
	p := testPolicy(t)
	for _, raw := range []string{
		"https://registry.npmjs.org/@anthropic-ai/claude-code",
		"https://registry.npmjs.org/%40anthropic-ai%2Fclaude-code",
		"https://registry.npmjs.org/%2540anthropic-ai%252Fclaude-code",
		"https://github.com/./anthropics/claude-code",
		"https://github.com/foo/../anthropics/claude-code",
		"https://github.com//anthropics/claude-code",
		"https://storage.googleapis.com/claude-code-dist-build/latest",
	} {
		u, err := url.Parse(raw)
		if err != nil || p.checkURL(u.Host, u) == nil {
			t.Errorf("accepted forbidden path %q", raw)
		}
	}
	u, _ := url.Parse("https://github.com/golang/go")
	if p.checkURL(u.Host, u) != nil {
		t.Fatal("blocked unrelated GitHub repository")
	}
}

type fixture struct {
	gateway *gateway
	server  *httptest.Server
	client  *http.Client
	mu      sync.Mutex
	targets []string
	origin  []string
}

func testTLSServer(t *testing.T, ca *authorityCA, host string, h http.Handler) *httptest.Server {
	t.Helper()
	cert, err := ca.leaf(host)
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewUnstartedServer(h)
	s.TLS = &tls.Config{Certificates: []tls.Certificate{*cert}, MinVersion: tls.VersionTLS12}
	s.StartTLS()
	t.Cleanup(s.Close)
	return s
}

func newFixture(t *testing.T, originHandler http.Handler) *fixture {
	t.Helper()
	f := &fixture{}
	issuer, err := newCA()
	if err != nil {
		t.Fatal(err)
	}
	root := x509.NewCertPool()
	root.AppendCertsFromPEM(issuer.public)
	if originHandler == nil {
		originHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			f.mu.Lock()
			f.origin = append(f.origin, r.Host+" "+r.RequestURI)
			f.mu.Unlock()
			w.Header().Set("Content-Type", "text/plain")
			io.WriteString(w, "fixture ok")
		})
	}
	origin := testTLSServer(t, issuer, "fixture.example.com", originHandler)
	plain := httptest.NewServer(originHandler)
	t.Cleanup(plain.Close)
	doh := testTLSServer(t, issuer, "cloudflare-dns.com", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, typ := r.URL.Query().Get("name"), r.URL.Query().Get("type")
		numericType := 1
		if typ == "AAAA" {
			numericType = 28
		}
		answer := []map[string]any{}
		add := func(kind int, data string) {
			answer = append(answer, map[string]any{"name": host, "type": kind, "TTL": 30, "data": data})
		}
		if typ == "A" {
			switch host {
			case "private.example.com":
				add(1, "127.0.0.1")
			case "metadata.example.com":
				add(1, "169.254.169.254")
			case "official-ip.example.com":
				add(1, "160.79.104.7")
			case "mixed.example.com":
				add(1, "93.184.216.34")
				add(1, "10.0.0.1")
			case "cname.example.com":
				add(5, "api.anthropic.com.")
				add(1, "93.184.216.34")
			default:
				add(1, "93.184.216.34")
			}
		} else if host == "ipv6-official.example.com" {
			add(28, "2607:6bc0::1")
		} else if host == "ipv6-private.example.com" {
			add(28, "::1")
		}
		w.Header().Set("Content-Type", "application/dns-json")
		json.NewEncoder(w).Encode(map[string]any{
			"Status": 0, "TC": false,
			"Question": []map[string]any{{"name": host, "type": numericType}},
			"Answer":   answer,
		})
	}))
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" {
			t.Error("gateway made a non-CONNECT request to upstream proxy")
			http.Error(w, "bad method", 403)
			return
		}
		f.mu.Lock()
		f.targets = append(f.targets, r.Host)
		f.mu.Unlock()
		var backend string
		switch r.Host {
		case "1.1.1.1:443", "1.0.0.1:443":
			backend = doh.Listener.Addr().String()
		case "93.184.216.34:443":
			backend = origin.Listener.Addr().String()
		case "93.184.216.34:80":
			backend = plain.Listener.Addr().String()
		default:
			http.Error(w, "unexpected numeric target", 403)
			return
		}
		up, err := net.DialTimeout("tcp", backend, time.Second)
		if err != nil {
			http.Error(w, "fixture unavailable", 502)
			return
		}
		down, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			up.Close()
			return
		}
		defer down.Close()
		defer up.Close()
		rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		rw.Flush()
		go func() {
			io.Copy(up, rw)
			up.Close()
		}()
		io.Copy(down, up)
	}))
	t.Cleanup(proxy.Close)
	g, err := newGateway(testPolicy(t), proxy.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	g.roots = root
	g.initDNSClient()
	t.Cleanup(func() { g.doh.CloseIdleConnections() })
	f.gateway = g
	f.server = httptest.NewServer(g)
	t.Cleanup(f.server.Close)
	proxyURL, _ := url.Parse(f.server.URL)
	clientRoots := x509.NewCertPool()
	clientRoots.AppendCertsFromPEM(g.ca.public)
	f.client = &http.Client{Transport: &http.Transport{
		Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: clientRoots},
	}, Timeout: 5 * time.Second}
	t.Cleanup(f.client.CloseIdleConnections)
	return f
}

func (f *fixture) counts() (originTargets, dnsTargets int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, target := range f.targets {
		if strings.HasPrefix(target, "1.1.1.1:") || strings.HasPrefix(target, "1.0.0.1:") {
			dnsTargets++
		} else {
			originTargets++
		}
	}
	return
}

func TestHTTPSIsInspectedAndPinned(t *testing.T) {
	f := newFixture(t, nil)
	resp, err := f.client.Get("https://fixture.example.com/ok?x=1")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "fixture ok" {
		t.Fatalf("unexpected response: %d %q", resp.StatusCode, body)
	}
	origins, dns := f.counts()
	if origins != 1 || dns == 0 {
		t.Fatalf("expected pinned origin+DoH, got origin=%d DoH=%d", origins, dns)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.origin) != 1 || f.origin[0] != "fixture.example.com /ok?x=1" {
		t.Fatalf("origin authority changed: %v", f.origin)
	}
	for _, target := range f.targets {
		host, _, err := net.SplitHostPort(target)
		if err != nil || net.ParseIP(host) == nil {
			t.Fatalf("upstream was allowed to resolve target: %q", target)
		}
	}
}

func TestPlainHTTPIsPinned(t *testing.T) {
	f := newFixture(t, nil)
	resp, err := f.client.Get("http://fixture.example.com/plain")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("HTTP returned %d", resp.StatusCode)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	found := false
	for _, target := range f.targets {
		found = found || target == "93.184.216.34:80"
	}
	if !found {
		t.Fatal("HTTP did not use pinned numeric CONNECT port 80")
	}
}

func TestForbiddenHostMakesNoUpstreamConnection(t *testing.T) {
	f := newFixture(t, nil)
	for _, host := range []string{
		"api.anthropic.com", "claude.ai", "browser-intake-us5-datadoghq.com",
		"127.0.0.1", "[2607:6bc0::1]", "api.anthropic.com.",
	} {
		r := httptest.NewRequest("CONNECT", "http://unused.example.com", nil)
		r.RequestURI, r.Host = host+":443", host+":443"
		w := httptest.NewRecorder()
		f.gateway.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Errorf("%s: got %d, want 403", host, w.Code)
		}
	}
	origins, dns := f.counts()
	if origins != 0 || dns != 0 {
		t.Fatalf("forbidden host contacted upstream: origin=%d DoH=%d", origins, dns)
	}
}

func TestForbiddenDNSMakesNoOriginConnection(t *testing.T) {
	f := newFixture(t, nil)
	for _, host := range []string{
		"private.example.com", "metadata.example.com", "official-ip.example.com",
		"mixed.example.com", "ipv6-official.example.com", "ipv6-private.example.com", "cname.example.com",
	} {
		r := httptest.NewRequest("CONNECT", "http://unused.example.com", nil)
		r.RequestURI, r.Host = host+":443", host+":443"
		w := httptest.NewRecorder()
		f.gateway.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Errorf("%s: got %d, want 403", host, w.Code)
		}
	}
	origins, dns := f.counts()
	if origins != 0 || dns == 0 {
		t.Fatalf("forbidden DNS reached origin: origin=%d DoH=%d", origins, dns)
	}
}

func (f *fixture) rawTLS(t *testing.T, sni string) (*tls.Conn, error) {
	t.Helper()
	c, err := net.DialTimeout("tcp", f.server.Listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(4 * time.Second))
	fmt.Fprint(c, "CONNECT fixture.example.com:443 HTTP/1.1\r\nHost: fixture.example.com:443\r\n\r\n")
	reader := bufio.NewReader(c)
	resp, err := http.ReadResponse(reader, &http.Request{Method: "CONNECT"})
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("CONNECT failed: response=%v err=%v", resp, err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(f.gateway.ca.public)
	tlsConn := tls.Client(&bufferedConn{Conn: c, reader: reader}, &tls.Config{RootCAs: roots, ServerName: sni})
	t.Cleanup(func() { tlsConn.Close() })
	return tlsConn, tlsConn.Handshake()
}

func TestSNIMismatchNeverReachesOrigin(t *testing.T) {
	f := newFixture(t, nil)
	if _, err := f.rawTLS(t, "other.example.com"); err == nil {
		t.Fatal("accepted mismatching SNI")
	}
	origins, _ := f.counts()
	if origins != 0 {
		t.Fatal("SNI mismatch contacted origin")
	}
}

func TestInnerAuthorityAndTunnelsRejected(t *testing.T) {
	for _, request := range []string{
		"GET / HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: fixture.example.com:80\r\n\r\n",
		"CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: fixture.example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
		"GET https://fixture.example.com/ HTTP/1.1\r\nHost: other.example.com\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: fixture.example.com\r\nHost: api.anthropic.com\r\n\r\n",
		"POST / HTTP/1.1\r\nHost: fixture.example.com\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nXX",
	} {
		t.Run(strings.Split(request, "\r\n")[0], func(t *testing.T) {
			f := newFixture(t, nil)
			c, err := f.rawTLS(t, "fixture.example.com")
			if err != nil {
				t.Fatal(err)
			}
			io.WriteString(c, request)
			resp, err := http.ReadResponse(bufio.NewReader(c), nil)
			if err != nil || (resp.StatusCode != 403 && resp.StatusCode != 400) {
				t.Fatalf("unsafe request accepted: resp=%v err=%v", resp, err)
			}
			resp.Body.Close()
			origins, _ := f.counts()
			if origins != 0 {
				t.Fatal("unsafe request reached origin")
			}
		})
	}
}

func TestUpstreamCertificateIsVerified(t *testing.T) {
	f := newFixture(t, nil)
	resp, err := f.client.Get("https://wrongcert.example.com/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 502 {
		t.Fatalf("wrong certificate accepted: %d", resp.StatusCode)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.origin) != 0 {
		t.Fatal("HTTP request reached wrong-certificate origin")
	}
}

func TestSSEStreamsBeforeOriginFinishes(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	closeRelease := func() { once.Do(func() { close(release) }) }
	defer closeRelease()
	f := newFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		<-release
		io.WriteString(w, "data: second\n\n")
	}))
	resp, err := f.client.Get("https://fixture.example.com/stream")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	line, err := bufio.NewReader(resp.Body).ReadString('\n')
	if err != nil || line != "data: first\n" {
		t.Fatalf("SSE was buffered: %q %v", line, err)
	}
	closeRelease()
}

func TestUpstreamFailureHasNoDirectFallback(t *testing.T) {
	f := newFixture(t, nil)
	f.gateway.proxy = "127.0.0.1:1"
	f.gateway.doh.CloseIdleConnections()
	resp, err := f.client.Get("http://fixture.example.com/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 502 {
		t.Fatalf("upstream unavailable did not fail closed: %d", resp.StatusCode)
	}
	origins, _ := f.counts()
	if origins != 0 {
		t.Fatal("unexpected origin connection after upstream failure")
	}
}
