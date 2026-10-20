package main

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

func deny(w http.ResponseWriter, status int) {
	w.Header().Set("Connection", "close")
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, http.StatusText(status), status)
}

func statusFor(err error) int {
	if errors.Is(err, errDenied) {
		return http.StatusForbidden
	}
	return http.StatusBadGateway
}

func (g *gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		g.connect(w, r)
		return
	}
	// The outer listener accepts ordinary HTTP absolute-form requests only.
	if r.URL.Scheme != "http" || r.URL.Host == "" || r.URL.Opaque != "" || r.URL.User != nil {
		deny(w, http.StatusForbidden)
		return
	}
	host, port, err := authority(r.URL.Host, "80")
	hh, hp, he := authority(r.Host, "80")
	if err != nil || he != nil || host != hh || port != hp || port != "80" ||
		g.policy.checkURL(host, r.URL) != nil || disallowedProtocol(r) {
		deny(w, http.StatusForbidden)
		return
	}
	ips, err := g.resolve(r.Context(), host)
	if err != nil {
		deny(w, statusFor(err))
		return
	}
	tr := g.transport(host, port, ips)
	defer tr.CloseIdleConnections()
	g.forward(w, r, host, "http", tr)
}

func disallowedProtocol(r *http.Request) bool {
	if r.Method == http.MethodConnect || r.Method == "PRI" ||
		r.Header.Get("Upgrade") != "" || r.Header.Get("Proxy-Connection") == "upgrade" {
		return true
	}
	for _, token := range strings.Split(r.Header.Get("Connection"), ",") {
		if strings.EqualFold(strings.TrimSpace(token), "upgrade") {
			return true
		}
	}
	return r.ProtoMajor != 1
}

func stripHopHeaders(h http.Header) {
	for _, v := range h.Values("Connection") {
		for _, key := range strings.Split(v, ",") {
			h.Del(strings.TrimSpace(key))
		}
	}
	for _, key := range []string{
		"Connection", "Proxy-Connection", "Proxy-Authenticate", "Proxy-Authorization",
		"Keep-Alive", "TE", "Trailer", "Transfer-Encoding", "Upgrade", "Alt-Svc",
	} {
		h.Del(key)
	}
}

func (g *gateway) forward(w http.ResponseWriter, r *http.Request, host, scheme string, tr *http.Transport) {
	req := r.Clone(r.Context())
	u := *r.URL
	u.Scheme, u.Host, u.User, u.Opaque, u.Fragment = scheme, host, nil, "", ""
	req.URL, req.Host, req.RequestURI = &u, host, ""
	req.Header = r.Header.Clone()
	stripHopHeaders(req.Header)
	resp, err := tr.RoundTrip(req)
	if err != nil {
		deny(w, statusFor(err))
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusSwitchingProtocols {
		deny(w, http.StatusForbidden)
		return
	}
	stripHopHeaders(resp.Header)
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	// Flush headers and every body chunk so long-running model SSE streams are
	// not accumulated. No request/response bodies are buffered or logged.
	controller := http.NewResponseController(w)
	_ = controller.Flush()
	buffer := make([]byte, 32*1024)
	for {
		n, readErr := resp.Body.Read(buffer)
		if n > 0 {
			if _, err = w.Write(buffer[:n]); err != nil {
				return
			}
			_ = controller.Flush()
		}
		if readErr == io.EOF {
			return
		}
		if readErr != nil {
			panic(http.ErrAbortHandler)
		}
	}
}

func (g *gateway) connect(w http.ResponseWriter, r *http.Request) {
	host, port, err := authority(r.RequestURI, "")
	hh, hp, he := authority(r.Host, "")
	if err != nil || he != nil || host != hh || port != hp || port != "443" ||
		g.policy.checkHost(host) != nil || r.ContentLength > 0 ||
		len(r.TransferEncoding) != 0 || r.Header.Get("Upgrade") != "" {
		deny(w, http.StatusForbidden)
		return
	}
	// Domain and DNS/IP policy is evaluated before any origin connection or
	// CONNECT success. Only trusted DoH may be contacted during resolution.
	ips, err := g.resolve(r.Context(), host)
	if err != nil {
		deny(w, statusFor(err))
		return
	}
	cert, err := g.ca.leaf(host)
	if err != nil {
		deny(w, http.StatusBadGateway)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		deny(w, http.StatusBadGateway)
		return
	}
	conn, rw, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	if _, err = rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil || rw.Flush() != nil {
		return
	}
	tlsConn := tls.Server(&bufferedConn{Conn: conn, reader: rw.Reader}, &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			sni, err := canonicalHost(hello.ServerName)
			if err != nil || sni != host {
				return nil, errDenied
			}
			// ECH cannot be accepted because no ECH keys are configured. A
			// client requiring ECH therefore fails, rather than tunnelling.
			return &tls.Config{
				MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"},
				Certificates: []tls.Certificate{*cert},
			}, nil
		},
	})
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	err = tlsConn.HandshakeContext(ctx)
	cancel()
	if err != nil {
		return
	}
	tr := g.transport(host, port, ips)
	defer tr.CloseIdleConnections()
	tracked := &trackedConn{Conn: tlsConn, done: make(chan struct{})}
	listener := &singleConnListener{conn: tracked}
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rh, rp, e := authority(r.Host, "443")
			if e != nil || rh != host || rp != "443" || disallowedProtocol(r) ||
				r.URL.User != nil || r.URL.Opaque != "" || r.URL.Fragment != "" ||
				g.policy.checkURL(host, r.URL) != nil {
				deny(w, http.StatusForbidden)
				return
			}
			// Clients inside CONNECT must use origin form. This also avoids
			// net/http's absolute-form authority normalization hiding a raw
			// conflicting Host header.
			if r.URL.IsAbs() || r.URL.Host != "" {
				deny(w, http.StatusForbidden)
				return
			}
			g.forward(w, r, host, "https", tr)
		}),
		ReadHeaderTimeout: 15 * time.Second, IdleTimeout: 90 * time.Second,
		MaxHeaderBytes: 32 * 1024,
		// TLS/HTTP parser errors must not log request details or credentials.
		ErrorLog: log.New(io.Discard, "", 0),
	}
	_ = server.Serve(listener)
}

type trackedConn struct {
	net.Conn
	done chan struct{}
	once sync.Once
}

func (c *trackedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.done) })
	return err
}

type singleConnListener struct {
	conn *trackedConn
	used bool
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	if !l.used {
		l.used = true
		return l.conn, nil
	}
	<-l.conn.done
	return nil, net.ErrClosed
}
func (l *singleConnListener) Addr() net.Addr { return l.conn.LocalAddr() }
func (l *singleConnListener) Close() error   { return l.conn.Close() }

// Explicit compile-time checks also keep accidental proxy interface drift out
// of Docker builds.
var _ http.Handler = (*gateway)(nil)
