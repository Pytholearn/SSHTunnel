// Package links parses SSH config share links:
//
//	npvt-ssh://<base64(json)>                      (NPV Tunnel)
//	ssh://<base64(user:pass@host:port)>#name       (base64 form)
//	ssh://user:pass@host:port/?hk=..&pk=..#name    (URI form, Hiddify/sing-box)
package links

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"sshtunnel/internal/config"
)

// DefaultUDPGWPort is used for ssh:// links, which carry no udpgw field.
const DefaultUDPGWPort = 7300

// ErrUnknown means the line is not an SSH link we understand.
var ErrUnknown = errors.New("unknown link format")

// Result of parsing a pasted block.
type Result struct {
	Profiles      []*config.Profile
	Subscriptions []string // http(s) URLs found in the text
	Skipped       int      // lines that were not SSH links (vless, vmess, junk...)
	Errors        []string // lines that looked like SSH links but failed to parse
}

// ParseText parses a pasted block: one link per line, or a base64 blob of such
// lines (subscription body). Unknown lines are counted in Skipped.
func ParseText(text string) Result {
	var r Result
	text = strings.TrimSpace(strings.TrimPrefix(text, string(rune(0xFEFF))))
	if text == "" {
		return r
	}
	// Whole block might be a base64 subscription body.
	if !strings.Contains(text, "://") {
		if dec, err := DecodeBase64(text); err == nil && strings.Contains(string(dec), "://") {
			text = string(dec)
		}
	}
	for _, line := range strings.FieldsFunc(text, func(c rune) bool { return c == '\n' || c == '\r' }) {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		low := strings.ToLower(line)
		if strings.HasPrefix(low, "http://") || strings.HasPrefix(low, "https://") {
			r.Subscriptions = append(r.Subscriptions, line)
			continue
		}
		p, err := Parse(line)
		switch {
		case errors.Is(err, ErrUnknown):
			r.Skipped++
		case err != nil:
			r.Errors = append(r.Errors, err.Error())
			r.Skipped++
		default:
			r.Profiles = append(r.Profiles, p)
		}
	}
	return r
}

// Parse parses a single link.
func Parse(link string) (*config.Profile, error) {
	link = strings.TrimSpace(link)
	low := strings.ToLower(link)
	switch {
	case strings.HasPrefix(low, "npvt-ssh://"):
		return parseNPVT(link[len("npvt-ssh://"):])
	case strings.HasPrefix(low, "ssh://"):
		return parseSSH(link[len("ssh://"):])
	}
	return nil, ErrUnknown
}

// DecodeBase64 accepts std or URL-safe alphabet, with or without padding,
// and ignores embedded whitespace.
func DecodeBase64(s string) ([]byte, error) {
	s = strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\r', '\n':
			return -1
		case '-':
			return '+'
		case '_':
			return '/'
		}
		return r
	}, s)
	s = strings.TrimRight(s, "=")
	return base64.RawStdEncoding.DecodeString(s)
}

// ---- npvt-ssh ----

func parseNPVT(body string) (*config.Profile, error) {
	raw, err := DecodeBase64(body)
	if err != nil {
		return nil, fmt.Errorf("npvt-ssh: bad base64: %w", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("npvt-ssh: bad json: %w", err)
	}
	str := func(k string) (string, error) {
		v, ok := m[k]
		if !ok || v == nil {
			return "", nil
		}
		s, ok := v.(string)
		if !ok {
			return fmt.Sprint(v), nil
		}
		return decodeNPVS(s)
	}
	num := func(k string) int {
		switch v := m[k].(type) {
		case float64:
			return int(v)
		case string:
			s, _ := decodeNPVS(v)
			n, _ := strconv.Atoi(s)
			return n
		}
		return 0
	}
	p := &config.Profile{Format: "npvt"}
	fields := []struct {
		key string
		dst *string
	}{
		{"sshConfigType", &p.SSHConfigType},
		{"remarks", &p.Name},
		{"sshHost", &p.Host},
		{"sshUsername", &p.Username},
		{"sshPassword", &p.Password},
		{"sshAuthMethod", &p.AuthMethod},
		{"sshPrivateKey", &p.PrivateKey},
		{"sshPrivateKeyPassphrase", &p.PrivateKeyPassphrase},
		{"sni", &p.SNI},
		{"tlsVersion", &p.TLSVersion},
		{"httpProxy", &p.HTTPProxy},
		{"payload", &p.Payload},
		{"dnsTTMode", &p.DNSTTMode},
	}
	for _, f := range fields {
		if *f.dst, err = str(f.key); err != nil {
			return nil, fmt.Errorf("npvt-ssh: field %s: %w", f.key, err)
		}
	}
	p.Port = num("sshPort")
	p.UDPGWPort = num("udpgwPort")
	if b, ok := m["udpgwTransparentDNS"].(bool); ok {
		p.UDPGWTransparentDNS = b
	}
	return finish(p)
}

func decodeNPVS(s string) (string, error) {
	if !strings.HasPrefix(s, "npvs1:") {
		return s, nil
	}
	b, err := DecodeBase64(s[len("npvs1:"):])
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ---- ssh:// ----

func parseSSH(body string) (*config.Profile, error) {
	main, frag, _ := strings.Cut(body, "#")
	name, err := url.PathUnescape(frag)
	if err != nil {
		name = frag
	}
	// URI form always contains '@' in clear text; '@' is not a base64 char.
	if strings.Contains(main, "@") {
		return parseSSHURI(main, name)
	}
	b64 := main
	if i := strings.IndexAny(b64, "/?"); i >= 0 {
		b64 = b64[:i]
	}
	dec, err := DecodeBase64(b64)
	if err != nil {
		return nil, fmt.Errorf("ssh: bad base64: %w", err)
	}
	s := strings.TrimSpace(string(dec))
	at := strings.LastIndex(s, "@")
	if at < 0 {
		return nil, errors.New("ssh: base64 payload has no user@host")
	}
	cred, hostport := s[:at], s[at+1:]
	user, pass, _ := strings.Cut(cred, ":")
	host, port, err := splitHostPort(hostport)
	if err != nil {
		return nil, fmt.Errorf("ssh: %w", err)
	}
	p := &config.Profile{
		Format: "ssh-b64", Name: name, Host: host, Port: port,
		Username: user, Password: pass, AuthMethod: "PASSWORD",
		UDPGWPort: DefaultUDPGWPort,
	}
	return finish(p)
}

func parseSSHURI(main, name string) (*config.Profile, error) {
	u, err := url.Parse("ssh://" + main)
	if err != nil {
		return nil, fmt.Errorf("ssh: %w", err)
	}
	if u.User == nil {
		return nil, errors.New("ssh: missing user")
	}
	pass, _ := u.User.Password()
	port := 22
	if ps := u.Port(); ps != "" {
		if port, err = strconv.Atoi(ps); err != nil {
			return nil, fmt.Errorf("ssh: bad port %q", ps)
		}
	}
	q := u.Query()
	p := &config.Profile{
		Format: "ssh-uri", Name: name, Host: u.Hostname(), Port: port,
		Username: u.User.Username(), Password: pass, AuthMethod: "PASSWORD",
		PinnedHostKey: strings.TrimSpace(q.Get("hk")),
		PrivateKey:    q.Get("pk"),
		UDPGWPort:     DefaultUDPGWPort,
	}
	if p.PrivateKey != "" && p.Password == "" {
		p.AuthMethod = "KEY"
	}
	if v := q.Get("udpgw"); v != "" {
		p.UDPGWPort, _ = strconv.Atoi(v)
	}
	return finish(p)
}

func splitHostPort(hp string) (string, int, error) {
	host, ps, err := net.SplitHostPort(hp)
	if err != nil {
		return "", 0, fmt.Errorf("bad host:port %q", hp)
	}
	port, err := strconv.Atoi(ps)
	if err != nil {
		return "", 0, fmt.Errorf("bad port %q", ps)
	}
	return host, port, nil
}

func finish(p *config.Profile) (*config.Profile, error) {
	p.Host = strings.TrimSpace(p.Host)
	if p.Host == "" {
		return nil, errors.New("missing host")
	}
	if p.Port <= 0 || p.Port > 65535 {
		return nil, fmt.Errorf("bad port %d", p.Port)
	}
	if p.Username == "" {
		return nil, errors.New("missing username")
	}
	if p.AuthMethod == "" {
		p.AuthMethod = "PASSWORD"
	}
	if strings.TrimSpace(p.Name) == "" {
		p.Name = fmt.Sprintf("%s@%s:%d", p.Username, p.Host, p.Port)
	}
	return p, nil
}
