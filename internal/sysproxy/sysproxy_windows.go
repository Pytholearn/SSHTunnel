//go:build windows

// Package sysproxy sets and restores the WinINet (per-user) system proxy.
// The previous settings are backed up to a file before changing anything, so
// they can be restored after a crash on the next start.
package sysproxy

import (
	"encoding/json"
	"errors"
	"os"
	"syscall"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const keyPath = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

// Bypass is the ProxyOverride value we set.
const Bypass = "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*;<local>"

// Settings is a snapshot of the proxy-related registry values.
type Settings struct {
	ProxyEnable      uint32 `json:"proxyEnable"`
	ProxyServer      string `json:"proxyServer"`
	ProxyOverride    string `json:"proxyOverride"`
	AutoConfigURL    string `json:"autoConfigURL"`
	HasProxyServer   bool   `json:"hasProxyServer"`
	HasProxyOverride bool   `json:"hasProxyOverride"`
	HasAutoConfigURL bool   `json:"hasAutoConfigURL"`
}

// Read returns the current settings.
func Read() (Settings, error) {
	var s Settings
	k, err := registry.OpenKey(registry.CURRENT_USER, keyPath, registry.QUERY_VALUE)
	if err != nil {
		return s, err
	}
	defer k.Close()
	if v, _, err := k.GetIntegerValue("ProxyEnable"); err == nil {
		s.ProxyEnable = uint32(v)
	}
	if v, _, err := k.GetStringValue("ProxyServer"); err == nil {
		s.ProxyServer, s.HasProxyServer = v, true
	}
	if v, _, err := k.GetStringValue("ProxyOverride"); err == nil {
		s.ProxyOverride, s.HasProxyOverride = v, true
	}
	if v, _, err := k.GetStringValue("AutoConfigURL"); err == nil {
		s.AutoConfigURL, s.HasAutoConfigURL = v, true
	}
	return s, nil
}

func write(s Settings) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, keyPath, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if err := k.SetDWordValue("ProxyEnable", s.ProxyEnable); err != nil {
		return err
	}
	set := func(name, val string, has bool) error {
		if has {
			return k.SetStringValue(name, val)
		}
		if err := k.DeleteValue(name); err != nil && !errors.Is(err, registry.ErrNotExist) && !errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) {
			return err
		}
		return nil
	}
	if err := set("ProxyServer", s.ProxyServer, s.HasProxyServer); err != nil {
		return err
	}
	if err := set("ProxyOverride", s.ProxyOverride, s.HasProxyOverride); err != nil {
		return err
	}
	if err := set("AutoConfigURL", s.AutoConfigURL, s.HasAutoConfigURL); err != nil {
		return err
	}
	notify()
	return nil
}

var (
	wininet           = windows.NewLazySystemDLL("wininet.dll")
	internetSetOption = wininet.NewProc("InternetSetOptionW")
)

const (
	optSettingsChanged = 39
	optRefresh         = 37
)

func notify() {
	_, _, _ = internetSetOption.Call(0, optSettingsChanged, 0, 0)
	_, _, _ = internetSetOption.Call(0, optRefresh, 0, 0)
}

// Manager applies the proxy and remembers how to undo it.
type Manager struct {
	BackupPath string
	active     bool
}

// Enable backs up the current settings (unless a backup already exists, which
// means a previous run crashed and the backup holds the real original) and
// points the system proxy at httpAddr ("127.0.0.1:10809").
func (m *Manager) Enable(httpAddr string) error {
	if _, err := os.Stat(m.BackupPath); errors.Is(err, os.ErrNotExist) {
		cur, err := Read()
		if err != nil {
			return err
		}
		b, _ := json.Marshal(cur)
		if err := os.WriteFile(m.BackupPath, b, 0o600); err != nil {
			return err
		}
	}
	m.active = true
	return write(Settings{
		ProxyEnable: 1,
		ProxyServer: httpAddr, HasProxyServer: true,
		ProxyOverride: Bypass, HasProxyOverride: true,
	})
}

// Active reports whether this manager changed the system proxy.
func (m *Manager) Active() bool { return m.active }

// Restore puts back the backed-up settings, if any, and deletes the backup.
// It is safe to call when nothing was changed. Returns true if it restored.
func (m *Manager) Restore() (bool, error) {
	m.active = false
	b, err := os.ReadFile(m.BackupPath)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var s Settings
	if err := json.Unmarshal(b, &s); err != nil {
		os.Remove(m.BackupPath)
		return false, err
	}
	if err := write(s); err != nil {
		return false, err
	}
	return true, os.Remove(m.BackupPath)
}
