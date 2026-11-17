package links

import (
	"encoding/base64"
	"strings"
	"testing"
)

const (
	sampleNPVT   = "npvt-ssh://eyJzc2hDb25maWdUeXBlIjoibnB2czE6VTFOSUxVUnBjbVZqZEE9PSIsInJlbWFya3MiOiJucHZzMTpVMU5JSUh3Z2RHVnpkQzExYzJWeSIsInNzaEhvc3QiOiJucHZzMTpjM05vTG1WNFlXMXdiR1V1WTI5dCIsInNzaFBvcnQiOjc3NzcsInNzaFVzZXJuYW1lIjoibnB2czE6YzNaZk1XRXlZak5qTkdRPSIsInNzaFBhc3N3b3JkIjoibnB2czE6V0hreE1tRmlNelJEWkE9PSIsInNzaEF1dGhNZXRob2QiOiJucHZzMTpVRUZUVTFkUFVrUT0iLCJzc2hQcml2YXRlS2V5IjoiIiwic3NoUHJpdmF0ZUtleVBhc3NwaHJhc2UiOiIiLCJzbmkiOiIiLCJ0bHNWZXJzaW9uIjoibnB2czE6UkVWR1FWVk1WQT09IiwiaHR0cFByb3h5IjoiIiwiYXV0aGVudGljYXRlUHJveHkiOmZhbHNlLCJwcm94eVVzZXJuYW1lIjoiIiwicHJveHlQYXNzd29yZCI6IiIsInBheWxvYWQiOiIiLCJkbnNUVE1vZGUiOiJucHZzMTpWVVJRIiwiZG5zU2VydmVyIjoiIiwibmFtZXNlcnZlciI6IiIsInB1YmxpY0tleSI6IiIsInVkcGd3UG9ydCI6NzMwMCwidWRwZ3dUcmFuc3BhcmVudEROUyI6dHJ1ZX0="
	sampleSSHB64 = "ssh://c3ZfMWEyYjNjNGQ6WHkxMmFiMzRDZEBzc2guZXhhbXBsZS5jb206Nzc3Nw==#test-user"
	sampleSSHURI = "ssh://sv_1a2b3c4d:Xy12ab34Cd@ssh.example.com:7777/?hk=ssh-ed25519%20AAAAC3NzaC1lZDI1NTE5AAAAIFizE8Mn%2BvP25T7%2BwBr8jIzytmV7CXagwFQRyNFKJd4B#SSH%20%7C%20test-user"
	sampleHK     = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFizE8Mn+vP25T7+wBr8jIzytmV7CXagwFQRyNFKJd4B"
)

func checkCommon(t *testing.T, name string, gotName, host string, port int, user, pass string) {
	t.Helper()
	if gotName != name {
		t.Errorf("name = %q, want %q", gotName, name)
	}
	if host != "ssh.example.com" || port != 7777 || user != "sv_1a2b3c4d" || pass != "Xy12ab34Cd" {
		t.Errorf("got %s:%d %s/%s", host, port, user, pass)
	}
}

func TestNPVT(t *testing.T) {
	p, err := Parse(sampleNPVT)
	if err != nil {
		t.Fatal(err)
	}
	checkCommon(t, "SSH | test-user", p.Name, p.Host, p.Port, p.Username, p.Password)
	if p.SSHConfigType != "SSH-Direct" || p.AuthMethod != "PASSWORD" || p.TLSVersion != "DEFAULT" || p.DNSTTMode != "UDP" {
		t.Errorf("raw fields: %q %q %q %q", p.SSHConfigType, p.AuthMethod, p.TLSVersion, p.DNSTTMode)
	}
	if p.UDPGWPort != 7300 || !p.UDPGWTransparentDNS {
		t.Errorf("udpgw = %d %v", p.UDPGWPort, p.UDPGWTransparentDNS)
	}
	if p.PrivateKey != "" || p.SNI != "" || p.Payload != "" {
		t.Errorf("empty fields not empty")
	}
}

func TestNPVTTolerant(t *testing.T) {
	body := strings.TrimPrefix(sampleNPVT, "npvt-ssh://")
	raw, _ := base64.StdEncoding.DecodeString(body)
	urlsafe := base64.RawURLEncoding.EncodeToString(raw)
	for _, in := range []string{
		"  " + sampleNPVT + " \r\n",
		"npvt-ssh://" + strings.TrimRight(body, "="),
		"NPVT-SSH://" + urlsafe,
	} {
		p, err := Parse(in)
		if err != nil {
			t.Fatalf("%q: %v", in[:20], err)
		}
		checkCommon(t, "SSH | test-user", p.Name, p.Host, p.Port, p.Username, p.Password)
	}
}

func TestSSHBase64(t *testing.T) {
	p, err := Parse(sampleSSHB64)
	if err != nil {
		t.Fatal(err)
	}
	checkCommon(t, "test-user", p.Name, p.Host, p.Port, p.Username, p.Password)
	if p.Format != "ssh-b64" || p.UDPGWPort != 7300 {
		t.Errorf("format=%s udpgw=%d", p.Format, p.UDPGWPort)
	}
	// Missing padding.
	p, err = Parse(strings.Replace(sampleSSHB64, "==", "", 1))
	if err != nil || p.Host != "ssh.example.com" {
		t.Fatalf("no padding: %v", err)
	}
}

func TestSSHURI(t *testing.T) {
	p, err := Parse(sampleSSHURI)
	if err != nil {
		t.Fatal(err)
	}
	checkCommon(t, "SSH | test-user", p.Name, p.Host, p.Port, p.Username, p.Password)
	if p.PinnedHostKey != sampleHK {
		t.Errorf("hk = %q", p.PinnedHostKey)
	}
	if p.Format != "ssh-uri" || p.PrivateKey != "" {
		t.Errorf("format=%s pk=%q", p.Format, p.PrivateKey)
	}
}

func TestSSHURIEscapedPassword(t *testing.T) {
	p, err := Parse("ssh://u:p%40ss%3Aw@[2001:db8::1]:22#x")
	if err != nil {
		t.Fatal(err)
	}
	if p.Password != "p@ss:w" || p.Host != "2001:db8::1" || p.Port != 22 {
		t.Errorf("%+v", p)
	}
	if p.Address() != "[2001:db8::1]:22" {
		t.Errorf("addr %s", p.Address())
	}
}

func TestMultiLine(t *testing.T) {
	text := "\n" + sampleNPVT + "\r\n" +
		"vless://abc@host:443?type=ws#v\n" +
		"   " + sampleSSHB64 + "   \n" +
		"garbage line\n\n" +
		sampleSSHURI + "\n" +
		"ssh://!!!notbase64#bad\n" +
		"https://sub.example.com/abc\n"
	r := ParseText(text)
	if len(r.Profiles) != 3 {
		t.Fatalf("profiles = %d", len(r.Profiles))
	}
	if r.Skipped != 3 { // vless, garbage, bad ssh
		t.Errorf("skipped = %d", r.Skipped)
	}
	if len(r.Errors) != 1 {
		t.Errorf("errors = %v", r.Errors)
	}
	if len(r.Subscriptions) != 1 {
		t.Errorf("subs = %v", r.Subscriptions)
	}
	// All three describe the same server -> same key.
	if r.Profiles[0].Key() != r.Profiles[1].Key() || r.Profiles[1].Key() != r.Profiles[2].Key() {
		t.Errorf("keys differ")
	}
}

func TestBase64Block(t *testing.T) {
	block := base64.StdEncoding.EncodeToString([]byte(sampleSSHB64 + "\nvmess://xyz\n" + sampleSSHURI))
	r := ParseText(block)
	if len(r.Profiles) != 2 || r.Skipped != 1 {
		t.Fatalf("profiles=%d skipped=%d", len(r.Profiles), r.Skipped)
	}
}

func TestBadInput(t *testing.T) {
	for _, in := range []string{
		"", "hello", "npvt-ssh://", "npvt-ssh://bm90IGpzb24=", "ssh://", "ssh://Zm9v#x",
		"ssh://dXNlcjpwYXNzQGhvc3Q6eHg=", // user:pass@host:xx
		"ssh://u:p@:22#nohost",
	} {
		if _, err := Parse(in); err == nil {
			t.Errorf("Parse(%q) succeeded", in)
		}
	}
	if r := ParseText("   \n\n "); len(r.Profiles) != 0 || r.Skipped != 0 {
		t.Errorf("blank text: %+v", r)
	}
}
