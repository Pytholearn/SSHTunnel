//go:build windows

package config

import (
	"encoding/base64"
	"unsafe"

	"golang.org/x/sys/windows"
)

var entropy = []byte("SSHTunnel/v1")

// Protect encrypts s for the current Windows user with DPAPI and returns base64.
func Protect(s string) (string, error) {
	if s == "" {
		return "", nil
	}
	in := blob([]byte(s))
	ent := blob(entropy)
	var out windows.DataBlob
	if err := windows.CryptProtectData(in, nil, ent, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return "", err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return base64.StdEncoding.EncodeToString(unsafe.Slice(out.Data, out.Size)), nil
}

// Unprotect reverses Protect.
func Unprotect(enc string) (string, error) {
	if enc == "" {
		return "", nil
	}
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return "", err
	}
	in := blob(raw)
	ent := blob(entropy)
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(in, nil, ent, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return "", err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return string(unsafe.Slice(out.Data, out.Size)), nil
}

func blob(b []byte) *windows.DataBlob {
	if len(b) == 0 {
		return &windows.DataBlob{}
	}
	return &windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
}
