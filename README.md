<p align="center"><img src="build/appicon.png" width="96" alt="SSH Tunnel"></p>

<h1 align="center">SSH Tunnel — Windows client</h1>

<p align="center">
  <b>Made By Hazard</b><br>
  Copy a link · press <kbd>Ctrl</kbd>+<kbd>V</kbd> · Connect
</p>

<p align="center">
  <a href="../../releases/latest"><img alt="Download" src="https://img.shields.io/badge/download-SSHTunnel.exe-2563eb?style=for-the-badge&logo=windows"></a>
  <img alt="Windows 10/11 x64" src="https://img.shields.io/badge/Windows-10%20%7C%2011%20x64-0f172a?style=for-the-badge">
  <img alt="Go + Wails" src="https://img.shields.io/badge/Go%20%2B%20Wails-v2-00add8?style=for-the-badge&logo=go">
  <a href="LICENSE"><img alt="MIT" src="https://img.shields.io/badge/license-MIT-22c55e?style=for-the-badge"></a>
</p>

<p align="center"><img src="docs/screenshot.png" width="720" alt="SSH Tunnel screenshot"></p>

<div dir="rtl">

## فارسی

یک برنامهٔ کوچک ویندوزی (فقط یک فایل exe) مثل v2rayN، ولی برای تونل SSH. لینک کانفیگ را کپی کنید، در برنامه
**Ctrl+V** بزنید (یا دکمهٔ «چسباندن»)، کانفیگ با اسمش در فهرست می‌آید؛ انتخابش کنید و «اتصال» را بزنید.

### امکانات
- وارد کردن با چسباندن: `npvt-ssh://`، `ssh://` (base64) و `ssh://user:pass@host:port/?hk=...` (Hiddify/sing-box)؛
  چند لینک در چند خط هم‌زمان؛ لینک‌های ناشناخته (vless/vmess…) نادیده گرفته و شمرده می‌شوند.
- کانفیگ تکراری (همان host + port + user) به‌روزرسانی می‌شود، نه اضافه.
- پروکسی محلی SOCKS5 (با DNS سمت سرور) روی `127.0.0.1:10808` و HTTP/HTTPS روی `127.0.0.1:10809` (قابل تغییر).
- تنظیم خودکار پروکسی سیستم و برگرداندن تنظیمات قبلی هنگام قطع، خروج، و حتی بعد از کرش (در اجرای بعدی).
- keepalive هر ۱۵ ثانیه، اتصال دوبارهٔ خودکار (۱، ۲، ۵، ۱۰، ۲۰ ثانیه)، نمایش سرعت/حجم/تأخیر/مدت اتصال.
- بررسی کلید سرور: اگر لینک `hk` دارد دقیقاً همان، وگرنه اولین کلید ذخیره می‌شود و در صورت تغییر سؤال می‌شود.
- رمزها با DPAPI ویندوز رمزنگاری می‌شوند و هیچ‌وقت در لاگ نوشته نمی‌شوند.
- آیکون کنار ساعت (اتصال/قطع/نمایش/خروج)، فقط یک نسخه از برنامه، اتصال خودکار هنگام اجرا، اجرا همراه ویندوز.
- رابط فارسی راست‌به‌چپ با گزینهٔ انگلیسی، تم تیره/روشن.
- **UDP** (تماس، بازی) از طریق badvpn-udpgw سرور (پورت `udpgwPort`، معمولاً 7300)؛ در SOCKS5 با UDP ASSOCIATE.
- **اشتراک (Subscription):** لینک `https://…` را بچسبانید یا از دکمهٔ «اشتراک‌ها» اضافه کنید؛ «به‌روزرسانی»
  کانفیگ‌های همان اشتراک را جایگزین می‌کند و حجم مصرفی/کل/انقضا نمایش داده می‌شود.
- **حالت TUN** (همهٔ برنامه‌ها، حتی آن‌هایی که پروکسی را نادیده می‌گیرند): در تنظیمات روشن کنید؛ برنامه یک بار
  با دسترسی ادمین دوباره اجرا می‌شود. DNS از طریق udpgw یا TCP داخل تونل می‌رود.
- **فهرست مستقیم:** دامنه/IP‌هایی مثل `*.ir` یا `192.168.0.0/16` که نباید از تونل بروند.

### دانلود
آخرین نسخهٔ `SSHTunnel.exe` را از بخش [Releases](../../releases/latest) بگیرید. نصب لازم ندارد.

### استفاده
1. `SSHTunnel.exe` را اجرا کنید (WebView2 روی ویندوز ۱۰/۱۱ هست؛ اگر نبود: https://developer.microsoft.com/microsoft-edge/webview2/).
2. لینک را کپی کنید و داخل برنامه Ctrl+V بزنید.
3. کانفیگ را انتخاب کنید و دکمهٔ بزرگ را بزنید (یا دوبار کلیک / Enter).
4. بستن پنجره برنامه را به کنار ساعت می‌برد؛ برای خروج از منوی آیکون «خروج» را بزنید.

کلیدهای میان‌بر: ↑/↓ انتخاب، Enter اتصال، Delete حذف، F2 ویرایش.

تست: وقتی وصل هستید
```
curl -x socks5h://127.0.0.1:10808 https://ifconfig.me
```
باید IP سرور را نشان دهد.

> نکته: اگر v2rayN هم‌زمان باز است، پورت 10808 را آن گرفته؛ از «تنظیمات» پورت‌ها را عوض کنید.

تنظیمات در `%APPDATA%\SSHTunnel\config.json` ذخیره می‌شود.

</div>

## English

**Download:** grab `SSHTunnel.exe` from [Releases](../../releases/latest) — no installer needed.

A small single-exe Windows 10/11 x64 app, like v2rayN but for SSH tunnels. Copy a config link, press **Ctrl+V**
in the window (or the Paste button), select the config and press Connect.

The client opens only `direct-tcpip` channels — it never requests a session, shell or pty, so it works with
users whose shell is `/bin/false` and `PermitTTY no`.

### Supported link formats

| Format | Example |
|---|---|
| NPV Tunnel | `npvt-ssh://` + base64(JSON); string values are `npvs1:` + base64(utf8) |
| ssh base64 | `ssh://` + base64(`user:pass@host:port`) + `#name` |
| ssh URI (Hiddify / sing-box) | `ssh://user:pass@host:port/?hk=<host key>&pk=<private key>#name` |
| subscription | `https://…` → base64 or plain list of the above (other protocols ignored) |

Parsing tolerates surrounding whitespace, missing padding, URL-safe base64, and multi-line pastes
(and a whole base64 subscription body). Unknown lines are skipped and counted.

### Features

- Local SOCKS5 (remote DNS: domain names are resolved by the server) and HTTP/HTTPS (CONNECT) proxy,
  default `127.0.0.1:10808` / `10809`, all multiplexed over one SSH connection.
- System proxy (WinINet: `ProxyEnable/ProxyServer/ProxyOverride`, `InternetSetOptionW` refresh). The previous
  settings are backed up to `%APPDATA%\SSHTunnel\proxy-backup.json` before changing them and restored on
  disconnect, on exit, and on the next start after a crash.
- `keepalive@openssh.com` every 15 s (also gives the latency number); 3 misses → reconnect with backoff
  1/2/5/10/20 s. Wrong password / rejected host key stop retrying.
- Host keys: `hk` from the link is verified strictly; otherwise trust-on-first-use per config; mismatch → dialog.
- Password + keyboard-interactive (answered with the password) + optional private key.
- Live status (state, uptime, bytes, speed, latency), latency test per config / all, sort by latency.
- Logs (last 500 lines) + copy, tray icon, single instance, connect on start, start with Windows
  (`--minimized` → starts in tray), Persian RTL / English, dark / light.
- Passwords are DPAPI-encrypted in `%APPDATA%\SSHTunnel\config.json`, never logged.

#### Phase 2

- **UDP via udpgw.** One direct-tcpip channel to `127.0.0.1:<udpgwPort>` carries all UDP flows using the
  badvpn-udpgw protocol (layout checked against badvpn's `udpgw_proto.h` / `udpgw.c`; unit test with known
  bytes, integration test against a real `badvpn-udpgw`). Keepalive every 10 s, REBIND on new conids, LRU
  conid reuse, DNS flag when `udpgwTransparentDNS` is set. Exposed as SOCKS5 UDP ASSOCIATE. DNS falls back
  to DNS-over-TCP through the tunnel when the server has no udpgw.
- **Subscriptions.** `https://…` lines in a paste or the Subscriptions dialog. Fetched with `ssh=uri` added to
  the query and a Hiddify-like User-Agent; only SSH links are imported. Update replaces that subscription's
  configs. `Subscription-Userinfo` (used/total/expire) and `Profile-Title` are shown. When connected the fetch
  goes through the tunnel first, then direct.
- **TUN mode.** Wintun adapter (`wintun.dll` 0.14.1, signed by WireGuard LLC, embedded and extracted next to the
  exe) + tun2socks' gVisor stack, with our own transport handler: TCP goes straight into the SSH dialer, UDP
  into udpgw (no local SOCKS hop). Routes `0.0.0.0/1`, `128.0.0.0/1` (and IPv6 halves) into the adapter; the SSH
  server IP gets a host route via the real gateway and the SSH socket is pinned to the physical interface
  (`IP_UNICAST_IF`), so there is no loop. Adapter DNS = 8.8.8.8 / 1.1.1.1. Needs admin: when TUN is enabled the
  app relaunches itself elevated (`--wait-pid`, `--connect`). Host routes are recorded in
  `%APPDATA%\SSHTunnel\tun-routes.json` and removed on the next start after a crash.
- **Direct (bypass) list.** Domains (`example.com`, `*.ir`) and IP/CIDR ranges that skip the tunnel in proxy
  mode (and IPs in TUN mode).

### Build

Requirements: Go 1.23+, Wails CLI v2 (`go install github.com/wailsapp/wails/v2/cmd/wails@v2.10.2`).
The frontend is plain HTML/CSS/JS in `frontend/dist` — no npm build step.

```
wails build -platform windows/amd64 -clean
```

Output: `build/bin/SSHTunnel.exe`. Optional installer: add `-nsis` (needs NSIS).
Icons are generated by `go run ./tools/genicon`.

### Tests

```
go test ./internal/...
```

Unit tests cover the three link parsers with the sample links (exact field values), multi-line and base64
pastes, bad input, the bypass matcher, and an end-to-end tunnel test against an in-process SSH server
(SOCKS5, HTTP, CONNECT, TOFU, pinned key, wrong password, server restart → auto-reconnect, and that no
session channel is ever requested).

Integration test against real OpenSSH (WSL or Docker), e.g. in WSL as root:

```
useradd -M -s /bin/false tunneltest && echo 'tunneltest:<password>' | chpasswd
# sshd config: Port 2222, PasswordAuthentication yes, AllowTcpForwarding yes, PermitTTY no, AllowUsers tunneltest
/usr/sbin/sshd -f /etc/ssh/sshd_tunneltest
cd /tmp/www && python3 -m http.server 8088 --bind 127.0.0.1
```

Then on Windows (PowerShell):

```
$env:SSHT_PASS='<password>'; $env:SSHT_HK='ssh-ed25519 AAAA...'   # /etc/ssh/ssh_host_ed25519_key.pub
$env:SSHT_STOP='wsl -d Ubuntu-20.04 -u root -- pkill sshd'
$env:SSHT_START='wsl -d Ubuntu-20.04 -u root -- /usr/sbin/sshd -f /etc/ssh/sshd_tunneltest'
$env:SSHT_SYSPROXY='1'   # also flips the real system proxy for a moment and checks it is restored
go test -tags integration -v ./integration
```

For the UDP test, run `badvpn-udpgw --listen-addr 127.0.0.1:7300` and a UDP echo server on `127.0.0.1:9999`
on the server side (`TestUDPGW`). `TUN_TEST_ADDR=<WSL-IP>:2222 go test ./internal/tun` checks the
interface-pinned dialer.

### Layout

```
main.go, app.go, tray.go     Wails app, bindings, tray
internal/links               link parsers
internal/config              profiles/settings store, DPAPI
internal/tunnel              SSH connection, keepalive, reconnect, host keys
internal/proxy               SOCKS5 + HTTP proxy, bypass rules
internal/sysproxy            WinINet system proxy set/restore
internal/udpgw               badvpn-udpgw client, SOCKS5 UDP relay, DNS-over-TCP fallback
internal/subs                subscription fetch / Subscription-Userinfo
internal/tun                 Wintun + gVisor TUN engine, routes, interface-pinned dialer
assets/wintun                wintun.dll (amd64) + its license
frontend/dist                UI (HTML/CSS/JS, Vazirmatn font, OFL)
```

### Credits & license

- **Made By Hazard** — released under the [MIT License](LICENSE).
- [Wails](https://wails.io), [golang.org/x/crypto/ssh](https://pkg.go.dev/golang.org/x/crypto/ssh),
  [tun2socks](https://github.com/xjasonlyu/tun2socks) / [gVisor](https://gvisor.dev) (TUN stack),
  [Wintun](https://www.wintun.net) (driver DLL, see `assets/wintun/LICENSE.txt`),
  [badvpn](https://github.com/ambrop72/badvpn) (udpgw protocol),
  [Vazirmatn](https://github.com/rastikerdar/vazirmatn) font (SIL OFL, `frontend/dist/fonts/OFL.txt`).

<p align="center"><sub>Made By Hazard</sub></p>
