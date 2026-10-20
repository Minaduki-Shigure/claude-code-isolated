package main

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func run() error {
	p, err := loadPolicy(env("POLICY_FILE", "/etc/claude-isolation/policy.json"))
	if err != nil {
		return err
	}
	g, err := newGateway(p, os.Getenv("UPSTREAM_PROXY_ADDR"))
	if err != nil {
		return err
	}
	ipc := env("IPC_DIR", "/run/claude-ipc")
	if err = os.MkdirAll(ipc, 0755); err != nil {
		return err
	}
	socket, ready := filepath.Join(ipc, "proxy.sock"), filepath.Join(ipc, "ready")
	_ = os.Remove(ready)
	_ = os.Remove(socket)
	if err = os.WriteFile(filepath.Join(ipc, "ca.pem"), g.ca.public, 0644); err != nil {
		return err
	}
	ln, err := net.Listen("unix", socket)
	if err != nil {
		return err
	}
	defer ln.Close()
	defer os.Remove(socket)
	defer os.Remove(ready)
	if err = os.Chmod(socket, 0666); err != nil {
		return err
	}
	server := &http.Server{
		Handler: g, ReadHeaderTimeout: 15 * time.Second, IdleTimeout: 90 * time.Second,
		MaxHeaderBytes: 32 * 1024, ErrorLog: log.New(io.Discard, "", 0),
	}
	if err = os.WriteFile(ready, []byte("ready\n"), 0644); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	err = server.Serve(ln)
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func main() {
	if run() != nil {
		// Never print errors that could contain URL paths or proxy credentials.
		os.Stderr.WriteString("isolation gateway failed\n")
		os.Exit(1)
	}
}
