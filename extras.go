package main

import (
	"context"
	"errors"
	"net"

	"sshtunnel/internal/config"
	"sshtunnel/internal/proxy"
	"sshtunnel/internal/tunnel"
)

// sessionExtras holds Phase 2 components (UDP via udpgw, TUN) that live as
// long as one connection.
type sessionExtras struct{}

func (sessionExtras) tunActive() bool { return false }
func (sessionExtras) udpActive() bool { return false }
func (sessionExtras) stop(func(string, ...any)) {}

func (a *App) startExtras(*config.Profile, config.Settings, *tunnel.Tunnel, *proxy.Server) {}

func recoverTunRoutes(string, func(string, ...any)) {}

func physicalDialer() func(context.Context, string) (net.Conn, error) { return nil }

func (a *App) AddSubscription(string) (string, error) {
	return "", errors.New("subscriptions are not supported yet")
}
