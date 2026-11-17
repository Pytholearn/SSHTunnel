package tunnel

import (
	"bytes"
	"fmt"
	"net"
	"strings"

	"golang.org/x/crypto/ssh"
)

// HostKeyPolicy implements pin / trust-on-first-use host key checking.
type HostKeyPolicy struct {
	Pinned string // authorized_keys line from the link (hk=), verified strictly
	Known  string // learned earlier (TOFU)

	// Confirm is called on a mismatch; return true to accept the new key.
	Confirm func(host, expectedFP, gotFP string) bool
	// Learn is called with the key line to remember for this profile.
	Learn func(keyLine string)
}

// KeyLine renders a public key as a single authorized_keys line.
func KeyLine(k ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))
}

func ParseKeyLine(line string) (ssh.PublicKey, error) {
	k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	return k, err
}

// Algorithms returns the host key algorithms to negotiate so the server
// presents the same key type we expect (nil = library default).
func (p HostKeyPolicy) Algorithms() []string {
	line := p.Pinned
	if line == "" {
		line = p.Known
	}
	if line == "" {
		return nil
	}
	k, err := ParseKeyLine(line)
	if err != nil {
		return nil
	}
	switch k.Type() {
	case ssh.KeyAlgoRSA:
		return []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA}
	default:
		return []string{k.Type()}
	}
}

// Callback returns the ssh.HostKeyCallback.
func (p HostKeyPolicy) Callback() ssh.HostKeyCallback {
	return func(hostname string, _ net.Addr, key ssh.PublicKey) error {
		expected := p.Pinned
		if expected == "" {
			expected = p.Known
		}
		if expected == "" {
			if p.Learn != nil {
				p.Learn(KeyLine(key))
			}
			return nil
		}
		want, err := ParseKeyLine(expected)
		if err == nil && bytes.Equal(want.Marshal(), key.Marshal()) {
			return nil
		}
		wantFP := "(invalid)"
		if err == nil {
			wantFP = ssh.FingerprintSHA256(want)
		}
		gotFP := ssh.FingerprintSHA256(key)
		if p.Confirm != nil && p.Confirm(hostname, wantFP, gotFP) {
			if p.Learn != nil {
				p.Learn(KeyLine(key))
			}
			return nil
		}
		return fmt.Errorf("%w: expected %s, got %s", ErrHostKeyRejected, wantFP, gotFP)
	}
}
