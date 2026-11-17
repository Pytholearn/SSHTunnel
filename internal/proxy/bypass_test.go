package proxy

import (
	"bytes"
	"testing"
)

func TestMatcher(t *testing.T) {
	m := NewMatcher([]string{"localhost", "10.0.0.0/8", "*.ir", "example.com", "1.2.3.4", "# comment", ""})
	cases := map[string]bool{
		"localhost": true, "10.1.2.3": true, "11.0.0.1": false,
		"digikala.ir": true, "www.digikala.ir": true, "ir": false, "iran.com": false,
		"example.com": true, "a.example.com": true, "badexample.com": false,
		"1.2.3.4": true, "[::1]": false, "EXAMPLE.COM.": true,
	}
	for h, want := range cases {
		if got := m(h); got != want {
			t.Errorf("%s: got %v want %v", h, got, want)
		}
	}
	if NewMatcher(nil) != nil {
		t.Error("empty rules should give nil matcher")
	}
}

func TestSOCKSAddrRoundTrip(t *testing.T) {
	for _, a := range []string{"1.2.3.4:80", "[2001:db8::1]:443", "example.com:8080"} {
		b, err := AppendSOCKSAddr(nil, a)
		if err != nil {
			t.Fatal(err)
		}
		got, err := ReadSOCKSAddr(bytes.NewReader(b))
		if err != nil || got != a {
			t.Errorf("%s -> %s (%v)", a, got, err)
		}
	}
}
