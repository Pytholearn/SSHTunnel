package proxy

import (
	"net"
	"strings"
)

// NewMatcher builds a "direct" predicate from rules like:
//
//	example.com     exact host or any subdomain
//	*.ir            any host ending in .ir
//	10.0.0.0/8      IP range (CIDR)
//	192.168.1.5     single IP
//
// Hosts given as domain names are only matched by domain rules (no local DNS
// lookup, which would leak queries).
func NewMatcher(rules []string) func(host string) bool {
	var nets []*net.IPNet
	var ips []net.IP
	var suffixes, exact []string
	for _, r := range rules {
		r = strings.ToLower(strings.TrimSpace(r))
		if r == "" || strings.HasPrefix(r, "#") {
			continue
		}
		if _, n, err := net.ParseCIDR(r); err == nil {
			nets = append(nets, n)
			continue
		}
		if ip := net.ParseIP(r); ip != nil {
			ips = append(ips, ip)
			continue
		}
		switch {
		case strings.HasPrefix(r, "*."):
			suffixes = append(suffixes, r[1:]) // ".ir"
		case strings.HasPrefix(r, "."):
			suffixes = append(suffixes, r)
		default:
			exact = append(exact, r)
			suffixes = append(suffixes, "."+r)
		}
	}
	if len(nets)+len(ips)+len(suffixes)+len(exact) == 0 {
		return nil
	}
	return func(host string) bool {
		host = strings.ToLower(strings.TrimSuffix(strings.Trim(host, "[]"), "."))
		if ip := net.ParseIP(host); ip != nil {
			for _, n := range nets {
				if n.Contains(ip) {
					return true
				}
			}
			for _, x := range ips {
				if x.Equal(ip) {
					return true
				}
			}
			return false
		}
		for _, e := range exact {
			if host == e {
				return true
			}
		}
		for _, s := range suffixes {
			if strings.HasSuffix(host, s) {
				return true
			}
		}
		return false
	}
}
