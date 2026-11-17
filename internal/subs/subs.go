// Package subs fetches subscription URLs (a base64 or plain list of links).
package subs

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"sshtunnel/internal/links"
)

// UserAgent looks Hiddify-like: servers only include the ssh:// URI line for
// Hiddify-style clients (or when ?ssh=uri is present, which we also add).
const UserAgent = "HiddifyNext/2.5.7 (windows) SSHTunnel/1.0"

// Info is the Subscription-Userinfo header.
type Info struct {
	Upload, Download, Total, Expire int64
}

// Result of a fetch.
type Result struct {
	Links links.Result
	Info  Info
	Title string
}

// FetchURL returns u with ssh=uri added to the query.
func FetchURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", errors.New("not an http(s) URL")
	}
	q := u.Query()
	if q.Get("ssh") == "" {
		q.Set("ssh", "uri")
	}
	u.RawQuery = q.Encode()
	u.Fragment = ""
	return u.String(), nil
}

// Fetch downloads and parses a subscription using client.
func Fetch(ctx context.Context, client *http.Client, raw string) (*Result, error) {
	fu, err := FetchURL(raw)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fu, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", UserAgent)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	res := &Result{
		Links: links.ParseText(string(body)),
		Info:  ParseUserinfo(resp.Header.Get("Subscription-Userinfo")),
		Title: decodeTitle(resp.Header.Get("Profile-Title")),
	}
	res.Links.Subscriptions = nil // never follow nested subscription URLs
	return res, nil
}

// ParseUserinfo parses "upload=1; download=2; total=3; expire=4".
func ParseUserinfo(h string) Info {
	var in Info
	for _, part := range strings.Split(h, ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		n, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		if err != nil {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "upload":
			in.Upload = int64(n)
		case "download":
			in.Download = int64(n)
		case "total":
			in.Total = int64(n)
		case "expire":
			in.Expire = int64(n)
		}
	}
	return in
}

func decodeTitle(h string) string {
	h = strings.TrimSpace(h)
	if b64, ok := strings.CutPrefix(h, "base64:"); ok {
		if b, err := base64.StdEncoding.DecodeString(b64); err == nil {
			return strings.TrimSpace(string(b))
		}
	}
	return h
}

// DefaultName derives a display name from the URL.
func DefaultName(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	if u.Fragment != "" {
		return u.Fragment
	}
	return u.Hostname()
}
