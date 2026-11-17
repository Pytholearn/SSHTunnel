package main

import (
	"os"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const runKey = `Software\Microsoft\Windows\CurrentVersion\Run`
const runValue = "SSHTunnel"

// setAutostart adds/removes the HKCU Run entry (starts minimized to tray).
func setAutostart(on bool) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if !on {
		if err := k.DeleteValue(runValue); err != nil && err != registry.ErrNotExist {
			return nil
		}
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return k.SetStringValue(runValue, `"`+exe+`" --minimized`)
}

func isAdmin() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

func startMinimized() bool {
	for _, a := range os.Args[1:] {
		if a == "--minimized" {
			return true
		}
	}
	return false
}
