package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
)

// Data is the full persisted document.
type Data struct {
	Settings      Settings        `json:"settings"`
	Profiles      []*Profile      `json:"profiles"`
	Subscriptions []*Subscription `json:"subscriptions"`
}

// Store loads and saves Data at a JSON path. All methods are safe for
// concurrent use; callers mutate via Update.
type Store struct {
	mu   sync.Mutex
	path string
	data Data
}

// AppDir returns %APPDATA%\SSHTunnel, creating it if needed.
func AppDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, "SSHTunnel")
	return dir, os.MkdirAll(dir, 0o700)
}

// Open loads the store at path (missing file = defaults).
func Open(path string) (*Store, error) {
	s := &Store{path: path, data: Data{Settings: DefaultSettings()}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &s.data); err != nil {
		return nil, err
	}
	d := DefaultSettings()
	if s.data.Settings.SocksPort == 0 {
		s.data.Settings.SocksPort = d.SocksPort
	}
	if s.data.Settings.HTTPPort == 0 {
		s.data.Settings.HTTPPort = d.HTTPPort
	}
	if s.data.Settings.Language == "" {
		s.data.Settings.Language = d.Language
	}
	if s.data.Settings.Theme == "" {
		s.data.Settings.Theme = d.Theme
	}
	if s.data.Settings.BypassList == nil {
		s.data.Settings.BypassList = d.BypassList
	}
	for _, p := range s.data.Profiles {
		p.Password, _ = Unprotect(p.PasswordEnc)
		p.PrivateKey, _ = Unprotect(p.PrivateKeyEnc)
		p.PrivateKeyPassphrase, _ = Unprotect(p.PassphraseEnc)
	}
	return s, nil
}

// View runs fn with read access to the data.
func (s *Store) View(fn func(d *Data)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.data)
}

// Update runs fn with write access and then saves.
func (s *Store) Update(fn func(d *Data) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := fn(&s.data); err != nil {
		return err
	}
	return s.saveLocked()
}

// Profile returns a copy of the profile with id, or nil.
func (s *Store) Profile(id string) *Profile {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.data.Profiles {
		if p.ID == id {
			c := *p
			return &c
		}
	}
	return nil
}

// Settings returns a copy of the settings.
func (s *Store) Settings() Settings {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.data.Settings
	st.BypassList = append([]string(nil), st.BypassList...)
	return st
}

func (s *Store) saveLocked() error {
	for _, p := range s.data.Profiles {
		var err error
		if p.PasswordEnc, err = Protect(p.Password); err != nil {
			return err
		}
		if p.PrivateKeyEnc, err = Protect(p.PrivateKey); err != nil {
			return err
		}
		if p.PassphraseEnc, err = Protect(p.PrivateKeyPassphrase); err != nil {
			return err
		}
	}
	b, err := json.MarshalIndent(&s.data, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// Merge adds profiles, replacing an existing one with the same Key (keeping
// its ID, name override and learned host key). Returns added/updated counts.
func (d *Data) Merge(in []*Profile) (added, updated int) {
	for _, np := range in {
		found := false
		for i, op := range d.Profiles {
			if op.Key() == np.Key() {
				np.ID = op.ID
				if np.KnownHostKey == "" && np.PinnedHostKey == "" {
					np.KnownHostKey = op.KnownHostKey
				}
				np.LastLatencyMs = op.LastLatencyMs
				if np.SubscriptionID == "" {
					np.SubscriptionID = op.SubscriptionID
				}
				d.Profiles[i] = np
				updated++
				found = true
				break
			}
		}
		if !found {
			if np.ID == "" {
				np.ID = NewID()
			}
			d.Profiles = append(d.Profiles, np)
			added++
		}
	}
	return
}
