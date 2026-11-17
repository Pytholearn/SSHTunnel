package main

import (
	"context"
	"embed"
	"log"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	waitForParent()
	app, err := NewApp()
	if err != nil {
		log.Fatal(err)
	}
	tray := newTray(app)

	err = wails.Run(&options.App{
		Title:            "SSH Tunnel",
		Width:            1000,
		Height:           700,
		MinWidth:         760,
		MinHeight:        520,
		StartHidden:      startMinimized(),
		BackgroundColour: &options.RGBA{R: 15, G: 23, B: 42, A: 255},
		AssetServer:      &assetserver.Options{Assets: assets},
		OnStartup: func(ctx context.Context) {
			app.startup(ctx)
			tray.start()
		},
		OnBeforeClose: app.beforeClose,
		OnShutdown: func(ctx context.Context) {
			app.shutdown(ctx)
			tray.stop()
		},
		SingleInstanceLock: &options.SingleInstanceLock{
			UniqueId:               "c6f3f0b2-4d5e-4f39-9a51-sshtunnel-app",
			OnSecondInstanceLaunch: func(options.SecondInstanceData) { app.ShowWindow() },
		},
		Bind: []interface{}{app},
		Windows: &windows.Options{
			Theme:                windows.SystemDefault,
			WebviewIsTransparent: false,
		},
	})
	if err != nil {
		log.Fatal(err)
	}
}
