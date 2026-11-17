package main

import (
	_ "embed"
	"runtime"
	"sync"

	"fyne.io/systray"
)

//go:embed assets/tray_on.ico
var trayOn []byte

//go:embed assets/tray_off.ico
var trayOff []byte

type tray struct {
	app      *App
	once     sync.Once
	mu       sync.Mutex
	ready    bool
	toggle   *systray.MenuItem
	lastOn   bool
	lastTip  string
	langFa   bool
	quitting bool
}

func newTray(a *App) *tray {
	t := &tray{app: a}
	a.trayUpdate = t.update
	return t
}

func (t *tray) start() {
	t.once.Do(func() {
		go func() {
			// The tray runs its own Win32 message loop on a dedicated thread.
			runtime.LockOSThread()
			systray.Run(t.onReady, func() {})
		}()
	})
}

func (t *tray) stop() {
	t.mu.Lock()
	t.quitting = true
	t.mu.Unlock()
	systray.Quit()
}

func (t *tray) labels() (connect, disconnect, show, exit string) {
	if t.app.store.Settings().Language == "en" {
		return "Connect", "Disconnect", "Show window", "Exit"
	}
	return "اتصال", "قطع اتصال", "نمایش برنامه", "خروج"
}

func (t *tray) onReady() {
	systray.SetIcon(trayOff)
	systray.SetTitle("SSH Tunnel")
	systray.SetTooltip("SSH Tunnel")
	connect, _, show, exit := t.labels()
	toggle := systray.AddMenuItem(connect, "")
	mShow := systray.AddMenuItem(show, "")
	systray.AddSeparator()
	mExit := systray.AddMenuItem(exit, "")
	systray.SetOnTapped(func() { t.app.ShowWindow() }) // left click
	t.mu.Lock()
	t.toggle, t.ready = toggle, true
	t.mu.Unlock()
	go func() {
		for {
			select {
			case <-toggle.ClickedCh:
				go t.app.ToggleConnection()
			case <-mShow.ClickedCh:
				t.app.ShowWindow()
			case <-mExit.ClickedCh:
				t.app.Quit()
				return
			}
		}
	}()
}

func (t *tray) update(on bool, tip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.ready || t.quitting || (on == t.lastOn && tip == t.lastTip) {
		return
	}
	connect, disconnect, _, _ := t.labels()
	if on != t.lastOn {
		if on {
			systray.SetIcon(trayOn)
		} else {
			systray.SetIcon(trayOff)
		}
	}
	t.app.mu.Lock()
	active := t.app.tun != nil
	t.app.mu.Unlock()
	if active {
		t.toggle.SetTitle(disconnect)
	} else {
		t.toggle.SetTitle(connect)
	}
	systray.SetTooltip(tip)
	t.lastOn, t.lastTip = on, tip
}
