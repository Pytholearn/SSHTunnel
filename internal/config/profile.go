// Package config holds the persistent data model (profiles, subscriptions,
// settings) and its on-disk store.
package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
)

// Profile is one SSH server config imported from a link or entered manually.
type Profile struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`

	// Password and PrivateKey live in memory only; on disk they are stored
	// DPAPI-encrypted in the *Enc fields.
	Password             string `json:"-"`
	PrivateKey           string `json:"-"`
	PrivateKeyPassphrase string `json:"-"`
	PasswordEnc          string `json:"passwordEnc,omitempty"`
	PrivateKeyEnc        string `json:"privateKeyEnc,omitempty"`
	PassphraseEnc        string `json:"passphraseEnc,omitempty"`

	AuthMethod string `json:"authMethod,omitempty"` // PASSWORD / KEY

	// PinnedHostKey comes from the link (hk=) and must match exactly.
	PinnedHostKey string `json:"pinnedHostKey,omitempty"`
	// KnownHostKey is learned on first use (TOFU) when no pin is given.
	KnownHostKey string `json:"knownHostKey,omitempty"`

	UDPGWPort           int  `json:"udpgwPort"`
	UDPGWTransparentDNS bool `json:"udpgwTransparentDns"`

	// Raw NPV fields kept for later phases (SSL / payload modes).
	SSHConfigType string `json:"sshConfigType,omitempty"`
	SNI           string `json:"sni,omitempty"`
	TLSVersion    string `json:"tlsVersion,omitempty"`
	HTTPProxy     string `json:"httpProxy,omitempty"`
	Payload       string `json:"payload,omitempty"`
	DNSTTMode     string `json:"dnsTTMode,omitempty"`

	Format         string `json:"format,omitempty"` // npvt / ssh-b64 / ssh-uri / manual
	SubscriptionID string `json:"subscriptionId,omitempty"`
	LastLatencyMs  int    `json:"lastLatencyMs,omitempty"` // -1 = failed, 0 = untested
}

// Key identifies a profile for duplicate detection: same host+port+user.
func (p *Profile) Key() string {
	return strings.ToLower(strings.TrimSpace(p.Host)) + "|" + fmt.Sprint(p.Port) + "|" + p.Username
}

// Address returns host:port suitable for net.Dial.
func (p *Profile) Address() string {
	h := p.Host
	if strings.Contains(h, ":") && !strings.HasPrefix(h, "[") {
		h = "[" + h + "]"
	}
	return fmt.Sprintf("%s:%d", h, p.Port)
}

// NewID returns a random 12-hex-char identifier.
func NewID() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// Subscription is a remote list of links that can be refreshed.
type Subscription struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	URL       string `json:"url"`
	UpdatedAt int64  `json:"updatedAt,omitempty"`
	// From the Subscription-Userinfo header (bytes / unix seconds).
	Upload   int64 `json:"upload,omitempty"`
	Download int64 `json:"download,omitempty"`
	Total    int64 `json:"total,omitempty"`
	Expire   int64 `json:"expire,omitempty"`
}

// Settings are the global app settings.
type Settings struct {
	SocksPort        int      `json:"socksPort"`
	HTTPPort         int      `json:"httpPort"`
	SystemProxy      bool     `json:"systemProxy"`
	ConnectOnStart   bool     `json:"connectOnStart"`
	StartWithWindows bool     `json:"startWithWindows"`
	Language         string   `json:"language"` // fa / en
	Theme            string   `json:"theme"`    // dark / light
	LastSelected     string   `json:"lastSelected"`
	TunMode          bool     `json:"tunMode"`
	BypassList       []string `json:"bypassList"`
}

// DefaultSettings returns first-run settings.
func DefaultSettings() Settings {
	return Settings{
		SocksPort:   10808,
		HTTPPort:    10809,
		SystemProxy: true,
		Language:    "fa",
		Theme:       "dark",
		BypassList:  []string{"localhost", "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"},
	}
}
