package main

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path"
	"strings"
)

var errDenied = errors.New("destination denied")

type pathRule struct {
	Host   string `json:"host"`
	Prefix string `json:"prefix"`
}

type dohConfig struct {
	Host         string   `json:"host"`
	Path         string   `json:"path"`
	BootstrapIPs []string `json:"bootstrap_ips"`
}

type policy struct {
	DenyDomains []string   `json:"deny_domains"`
	DenyCIDRs   []string   `json:"deny_cidrs"`
	DenyPaths   []pathRule `json:"deny_paths"`
	DoH         dohConfig  `json:"doh"`
	prefixes    []netip.Prefix
}

// These restrictions are not configurable away. Besides RFC1918/ULA, reject
// documentation, transition, multicast, benchmarking and special-use ranges.
// IPv6 is restricted to current global-unicast 2000::/3 before these exclusions.
var reserved = []string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
	"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
	"192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
	"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
	"224.0.0.0/4", "240.0.0.0/4",
	"2001::/23", "2001:db8::/32", "2002::/16",
	"3ffe::/16", "3fff::/20",
	// Anthropic's documented ranges are mandatory, even with a custom policy.
	"160.79.104.0/21", "2607:6bc0::/48",
}

var mandatoryDomains = []string{
	"anthropic.com", "claude.ai", "claude.com",
	"claudeusercontent.com", "claudemcpcontent.com",
}

func loadPolicy(path string) (*policy, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 1<<20))
	d.DisallowUnknownFields()
	var p policy
	if err = d.Decode(&p); err != nil {
		return nil, err
	}
	var extra any
	if err = d.Decode(&extra); err != io.EOF {
		return nil, errors.New("trailing policy data")
	}
	return p.validate()
}

func (p *policy) validate() (*policy, error) {
	p.prefixes = nil
	for _, s := range append(append([]string{}, reserved...), p.DenyCIDRs...) {
		n, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, errors.New("invalid denied CIDR")
		}
		p.prefixes = append(p.prefixes, n.Masked())
	}
	p.DenyDomains = append(p.DenyDomains, mandatoryDomains...)
	for i, s := range p.DenyDomains {
		h, err := canonicalHost(s)
		if err != nil {
			return nil, errors.New("invalid denied domain")
		}
		p.DenyDomains[i] = h
	}
	for i := range p.DenyPaths {
		h, err := canonicalHost(p.DenyPaths[i].Host)
		if err != nil || !strings.HasPrefix(p.DenyPaths[i].Prefix, "/") {
			return nil, errors.New("invalid denied path")
		}
		p.DenyPaths[i].Host = h
		p.DenyPaths[i].Prefix = strings.ToLower(p.DenyPaths[i].Prefix)
	}
	h, err := canonicalHost(p.DoH.Host)
	if err != nil || !strings.HasPrefix(p.DoH.Path, "/") ||
		strings.ContainsAny(p.DoH.Path, "?#\\") || len(p.DoH.BootstrapIPs) == 0 {
		return nil, errors.New("invalid DoH configuration")
	}
	p.DoH.Host = h
	if p.checkHost(h) != nil {
		return nil, errors.New("DoH host denied")
	}
	for _, s := range p.DoH.BootstrapIPs {
		a, e := netip.ParseAddr(s)
		if e != nil || p.checkIP(a) != nil {
			return nil, errors.New("DoH bootstrap IP denied")
		}
	}
	return p, nil
}

func canonicalHost(h string) (string, error) {
	// ASCII/punycode only. Never accept URL/userinfo, numeric addresses, zone
	// identifiers, alternate IP representations or DNS search-list names.
	h = strings.ToLower(h)
	if strings.HasSuffix(h, ".") {
		h = strings.TrimSuffix(h, ".")
	}
	if len(h) > 253 || len(h) == 0 || !strings.Contains(h, ".") {
		return "", errDenied
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return "", errDenied
	}
	labels := strings.Split(h, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errDenied
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", errDenied
			}
		}
	}
	// Reject numeric/hex pseudo-TLDs used by alternate IP parsers.
	tld := labels[len(labels)-1]
	hasLetter := false
	for _, c := range tld {
		if c >= 'a' && c <= 'z' {
			hasLetter = true
		}
	}
	if !hasLetter || strings.HasPrefix(tld, "0x") {
		return "", errDenied
	}
	return h, nil
}

func authority(s, defaultPort string) (string, string, error) {
	if strings.ContainsAny(s, "@/#?\\% \t\r\n") {
		return "", "", errDenied
	}
	h, port, err := net.SplitHostPort(s)
	if err != nil {
		if strings.Contains(s, ":") || defaultPort == "" {
			return "", "", errDenied
		}
		h, port = s, defaultPort
	}
	h, err = canonicalHost(h)
	if err != nil || (port != "80" && port != "443") {
		return "", "", errDenied
	}
	return h, port, nil
}

func (p *policy) checkHost(host string) error {
	h, err := canonicalHost(host)
	if err != nil {
		return errDenied
	}
	for _, d := range p.DenyDomains {
		if h == d || strings.HasSuffix(h, "."+d) {
			return errDenied
		}
	}
	for _, d := range []string{
		"localhost", "local", "internal", "home", "lan",
		"test", "invalid", "example", "onion", "arpa",
	} {
		if h == d || strings.HasSuffix(h, "."+d) {
			return errDenied
		}
	}
	return nil
}

func (p *policy) checkIP(a netip.Addr) error {
	// IPv4-mapped IPv6 would give different interpretations across layers.
	if !a.IsValid() || a.Is4In6() || a.Zone() != "" || !a.IsGlobalUnicast() {
		return errDenied
	}
	if a.Is6() && !netip.MustParsePrefix("2000::/3").Contains(a) {
		return errDenied
	}
	for _, n := range p.prefixes {
		if n.Contains(a) {
			return errDenied
		}
	}
	return nil
}

func (p *policy) checkURL(host string, u *url.URL) error {
	if err := p.checkHost(host); err != nil {
		return err
	}
	requestPath := u.EscapedPath()
	// Recognize encoded scope/slash forms, reject excessive ambiguous escaping.
	for i := 0; i < 4; i++ {
		decoded, err := url.PathUnescape(requestPath)
		if err != nil {
			return errDenied
		}
		if decoded == requestPath {
			break
		}
		requestPath = decoded
	}
	if strings.Contains(requestPath, "%") || strings.ContainsAny(requestPath, "\\\x00\r\n") {
		return errDenied
	}
	requestPath = strings.ToLower(path.Clean("/" + strings.TrimLeft(requestPath, "/")))
	for _, rule := range p.DenyPaths {
		if host == rule.Host && strings.HasPrefix(requestPath, rule.Prefix) {
			return errDenied
		}
	}
	return nil
}
