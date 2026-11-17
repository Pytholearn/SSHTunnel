package subs

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const sshURI = "ssh://sv_1a2b3c4d:Xy12ab34Cd@ssh.example.com:7777/?hk=ssh-ed25519%20AAAAC3NzaC1lZDI1NTE5AAAAIFizE8Mn%2BvP25T7%2BwBr8jIzytmV7CXagwFQRyNFKJd4B#SSH%20%7C%20test-user"

func TestFetch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lines := []string{"vless://x@h:443#v", "vmess://abc"}
		if r.URL.Query().Get("ssh") == "uri" && strings.Contains(strings.ToLower(r.UserAgent()), "hiddify") {
			lines = append(lines, sshURI)
		}
		w.Header().Set("Subscription-Userinfo", "upload=100; download=2.5e3; total=10737418240; expire=1798000000")
		w.Header().Set("Profile-Title", "base64:"+base64.StdEncoding.EncodeToString([]byte("سرویس من")))
		w.Write([]byte(base64.StdEncoding.EncodeToString([]byte(strings.Join(lines, "\n")))))
	}))
	defer srv.Close()
	res, err := Fetch(context.Background(), srv.Client(), srv.URL+"/sub/abc?x=1#mine")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Links.Profiles) != 1 || res.Links.Skipped != 2 {
		t.Fatalf("profiles=%d skipped=%d", len(res.Links.Profiles), res.Links.Skipped)
	}
	if p := res.Links.Profiles[0]; p.Host != "ssh.example.com" || p.Password != "Xy12ab34Cd" {
		t.Fatalf("%+v", p)
	}
	if res.Info != (Info{Upload: 100, Download: 2500, Total: 10737418240, Expire: 1798000000}) {
		t.Fatalf("info %+v", res.Info)
	}
	if res.Title != "سرویس من" {
		t.Fatalf("title %q", res.Title)
	}
}

func TestFetchURL(t *testing.T) {
	u, err := FetchURL("https://a.example/sub?token=1#n")
	if err != nil || u != "https://a.example/sub?ssh=uri&token=1" {
		t.Fatalf("%s %v", u, err)
	}
	if _, err := FetchURL("ftp://x"); err == nil {
		t.Fatal("ftp accepted")
	}
	if DefaultName("https://a.example/sub#mine") != "mine" || DefaultName("https://a.example/sub") != "a.example" {
		t.Fatal("names")
	}
}
