"use strict";

// ---------- i18n ----------
const T = {
  fa: {
    paste: "چسباندن", pasteHint: "وارد کردن لینک از کلیپ‌بورد", add: "افزودن", subscriptions: "اشتراک‌ها",
    testAll: "تست همه", sort: "مرتب‌سازی", settings: "تنظیمات", theme: "تم روشن/تیره",
    configs: "کانفیگ‌ها", emptyTitle: "هنوز کانفیگی ندارید", emptyHint: "لینک را کپی کنید و Ctrl+V بزنید",
    uptime: "مدت اتصال", latency: "تأخیر", upload: "ارسال", download: "دریافت",
    systemProxy: "پروکسی سیستم", logs: "گزارش‌ها", copyLogs: "کپی گزارش",
    fName: "نام", fHost: "آدرس سرور", fPort: "پورت", fUser: "نام کاربری", fPass: "رمز عبور",
    fUdpgw: "پورت UDPGW", fHostKey: "کلید سرور (اختیاری)", fKeyAuth: "کلید خصوصی (اختیاری)",
    forgetKey: "فراموش کردن کلید ذخیره‌شده", cancel: "انصراف", save: "ذخیره", close: "بستن",
    socksPort: "پورت SOCKS5", httpPort: "پورت HTTP", systemProxyOnConnect: "تنظیم پروکسی سیستم هنگام اتصال",
    connectOnStart: "اتصال خودکار هنگام اجرا", startWithWindows: "اجرا همراه ویندوز",
    tunMode: "حالت TUN (همهٔ برنامه‌ها، نیاز به دسترسی ادمین)", bypass: "فهرست مستقیم (بدون تونل) — هر خط یکی",
    portsNote: "تغییر پورت‌ها و TUN از اتصال بعدی اعمال می‌شود.", addSub: "افزودن",
    newConfig: "کانفیگ جدید", editConfig: "ویرایش کانفیگ",
    connect: "اتصال", disconnect: "قطع", connecting: "در حال اتصال…", cancelConn: "لغو",
    s_disconnected: "قطع", s_connecting: "در حال اتصال", s_connected: "متصل", s_reconnecting: "اتصال دوباره", s_error: "خطا",
    test: "تست تأخیر", edit: "ویرایش", del: "حذف", confirmDelete: "«{0}» حذف شود؟",
    imported: "{0} کانفیگ اضافه شد", updated: "{0} به‌روز شد", skipped: "{0} خط نادیده گرفته شد",
    subsAdded: "{0} اشتراک اضافه شد", nothing: "لینک SSH معتبری در کلیپ‌بورد نبود",
    copied: "کپی شد", selectFirst: "اول یک کانفیگ انتخاب کنید", failed: "ناموفق", testing: "در حال تست…",
    update: "به‌روزرسانی", remove: "حذف", used: "مصرف", expire: "انقضا", configsN: "{0} کانفیگ",
    never: "هرگز", unlimited: "نامحدود", tunNeedsAdmin: "برای TUN برنامه با دسترسی ادمین دوباره اجرا می‌شود",
    udp: "UDP", tun: "TUN", saved: "ذخیره شد",
  },
  en: {
    paste: "Paste", pasteHint: "Import link from clipboard", add: "Add", subscriptions: "Subscriptions",
    testAll: "Test all", sort: "Sort", settings: "Settings", theme: "Light/dark theme",
    configs: "Configs", emptyTitle: "No configs yet", emptyHint: "Copy a link and press Ctrl+V",
    uptime: "Uptime", latency: "Latency", upload: "Upload", download: "Download",
    systemProxy: "System proxy", logs: "Logs", copyLogs: "Copy logs",
    fName: "Name", fHost: "Host", fPort: "Port", fUser: "Username", fPass: "Password",
    fUdpgw: "UDPGW port", fHostKey: "Host key (optional)", fKeyAuth: "Private key (optional)",
    forgetKey: "Forget saved key", cancel: "Cancel", save: "Save", close: "Close",
    socksPort: "SOCKS5 port", httpPort: "HTTP port", systemProxyOnConnect: "Set system proxy when connected",
    connectOnStart: "Connect on start", startWithWindows: "Start with Windows",
    tunMode: "TUN mode (all apps, needs admin)", bypass: "Direct (bypass) list — one per line",
    portsNote: "Port and TUN changes apply on next connect.", addSub: "Add",
    newConfig: "New config", editConfig: "Edit config",
    connect: "Connect", disconnect: "Disconnect", connecting: "Connecting…", cancelConn: "Cancel",
    s_disconnected: "Disconnected", s_connecting: "Connecting", s_connected: "Connected", s_reconnecting: "Reconnecting", s_error: "Error",
    test: "Test latency", edit: "Edit", del: "Delete", confirmDelete: "Delete “{0}”?",
    imported: "{0} added", updated: "{0} updated", skipped: "{0} lines skipped",
    subsAdded: "{0} subscriptions added", nothing: "No valid SSH link in clipboard",
    copied: "Copied", selectFirst: "Select a config first", failed: "failed", testing: "testing…",
    update: "Update", remove: "Remove", used: "Used", expire: "Expires", configsN: "{0} configs",
    never: "never", unlimited: "unlimited", tunNeedsAdmin: "The app will restart as administrator for TUN",
    udp: "UDP", tun: "TUN", saved: "Saved",
  },
};
let lang = "fa";
const t = (k, ...a) => (T[lang][k] ?? k).replace(/\{(\d)\}/g, (_, i) => a[i]);

// ---------- backend (Wails, or a mock for browser preview) ----------
const api = window.go?.main?.App ?? mockApi();
const on = (ev, fn) => (window.runtime ? window.runtime.EventsOn(ev, fn) : mockOn(ev, fn));

// ---------- state ----------
const S = { profiles: [], subs: [], settings: {}, status: { state: "disconnected" }, selected: "", testing: new Set() };
const $ = (s) => document.querySelector(s);

function applyLang() {
  document.documentElement.lang = lang;
  document.documentElement.dir = lang === "fa" ? "rtl" : "ltr";
  document.querySelectorAll("[data-i18n]").forEach((el) => (el.textContent = t(el.dataset.i18n)));
  document.querySelectorAll("[data-i18n-title]").forEach((el) => (el.title = t(el.dataset.i18nTitle)));
  $("#btnLang").textContent = lang === "fa" ? "EN" : "فا";
  renderList();
  renderStatus();
}

function applyTheme() {
  document.documentElement.dataset.theme = S.settings.theme === "light" ? "light" : "dark";
}

// ---------- formatting ----------
const fmtBytes = (n) => {
  if (!n) return "0 B";
  const u = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.min(Math.floor(Math.log(n) / Math.log(1024)), u.length - 1);
  return (n / 1024 ** i).toFixed(i ? 1 : 0) + " " + u[i];
};
const fmtDur = (s) => {
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), x = s % 60;
  return [h, m, x].map((v) => String(v).padStart(2, "0")).join(":");
};
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

function toast(msg, err = false) {
  const el = $("#toast");
  el.textContent = msg;
  el.className = "toast show" + (err ? " err" : "");
  clearTimeout(toast.t);
  toast.t = setTimeout(() => (el.className = "toast" + (err ? " err" : "")), err ? 4500 : 2600);
}

// ---------- list ----------
function latencyBadge(p) {
  if (S.testing.has(p.id)) return `<span class="badge">…</span>`;
  const ms = p.latencyMs;
  if (!ms) return `<span class="badge">—</span>`;
  if (ms < 0) return `<span class="badge bad">${t("failed")}</span>`;
  const cls = ms < 300 ? "good" : ms < 800 ? "mid" : "bad";
  return `<span class="badge ${cls}">${ms} ms</span>`;
}

function renderList() {
  const list = $("#list");
  $("#count").textContent = S.profiles.length;
  $("#empty").classList.toggle("hidden", S.profiles.length > 0);
  const activeId = S.status.state !== "disconnected" && S.status.state !== "error" ? S.status.profileId : "";
  list.innerHTML = S.profiles.map((p) => {
    const sub = p.subId ? S.subs.find((s) => s.id === p.subId) : null;
    return `
    <div class="item ${p.id === S.selected ? "selected" : ""}" data-id="${esc(p.id)}" role="option">
      <div class="meta">
        <div class="name">${p.id === activeId ? '<span class="live"></span>' : ""}${esc(p.name)}${sub ? `<span class="tag">${esc(sub.name)}</span>` : ""}</div>
        <div class="host">${esc(p.username)}@${esc(p.host)}:${p.port}</div>
      </div>
      ${latencyBadge(p)}
      <div class="tools">
        <button class="tool" data-act="test" title="${t("test")}">⏱</button>
        <button class="tool" data-act="edit" title="${t("edit")}">✎</button>
        <button class="tool danger" data-act="del" title="${t("del")}">🗑</button>
      </div>
    </div>`;
  }).join("");
}

$("#list").addEventListener("click", async (e) => {
  const item = e.target.closest(".item");
  if (!item) return;
  const id = item.dataset.id;
  const act = e.target.closest("[data-act]")?.dataset.act;
  select(id);
  if (act === "test") testOne(id);
  if (act === "edit") openEdit(id);
  if (act === "del") {
    const p = S.profiles.find((x) => x.id === id);
    if (confirm(t("confirmDelete", p?.name ?? ""))) {
      try { await api.DeleteProfile(id); } catch (err) { toast(String(err), true); }
    }
  }
});
$("#list").addEventListener("dblclick", (e) => {
  const item = e.target.closest(".item");
  if (item && !e.target.closest("[data-act]")) connect(item.dataset.id);
});

function select(id) {
  if (S.selected === id) return;
  S.selected = id;
  api.SelectProfile(id);
  renderList();
  renderStatus();
}

async function testOne(id) {
  S.testing.add(id);
  renderList();
  try { await api.TestLatency(id); } catch (_) { /* shown as failed */ }
  S.testing.delete(id);
  renderList();
}

// ---------- status ----------
function renderStatus() {
  const s = S.status;
  const st = s.state || "disconnected";
  $("#dot").className = "dot " + st;
  $("#stateText").textContent = t("s_" + st);
  const active = st === "connected" || st === "connecting" || st === "reconnecting";
  const sel = S.profiles.find((p) => p.id === S.selected);
  $("#profileName").textContent = active ? s.profileName || "—" : sel?.name || "—";
  const btn = $("#btnConnect");
  btn.className = "connect" + (st === "connected" ? " on" : active ? " busy" : "");
  $("#connectLabel").textContent = st === "connected" ? t("disconnect") : active ? t("cancelConn") : t("connect");
  $("#detail").textContent = st === "connected" ? "" : s.detail || "";
  $("#uptime").textContent = st === "connected" ? fmtDur(s.uptimeSec || 0) : "—";
  $("#latency").textContent = st === "connected" && s.latencyMs ? s.latencyMs + " ms" : "—";
  $("#up").textContent = active ? fmtBytes(s.up) : "—";
  $("#down").textContent = active ? fmtBytes(s.down) : "—";
  $("#upSpeed").textContent = active ? fmtBytes(s.upSpeed) + "/s" : "";
  $("#downSpeed").textContent = active ? fmtBytes(s.downSpeed) + "/s" : "";
  $("#swSysProxy").checked = !!S.settings.systemProxy;
  const tags = [];
  if (s.tunActive) tags.push(t("tun"));
  if (s.udpActive) tags.push(t("udp"));
  $("#addrs").textContent = active
    ? `SOCKS5 ${s.socksAddr}  ·  HTTP ${s.httpAddr}${tags.length ? "  ·  " + tags.join(" + ") : ""}`
    : `SOCKS5 127.0.0.1:${S.settings.socksPort}  ·  HTTP 127.0.0.1:${S.settings.httpPort}`;
}

async function connect(id) {
  if (!id) return toast(t("selectFirst"), true);
  try { await api.Connect(id); } catch (err) { toast(String(err), true); }
}

$("#btnConnect").addEventListener("click", async () => {
  const st = S.status.state;
  if (st === "connected" || st === "connecting" || st === "reconnecting") {
    await api.Disconnect();
  } else {
    connect(S.selected);
  }
});

$("#swSysProxy").addEventListener("change", async (e) => {
  const s = { ...S.settings, systemProxy: e.target.checked };
  try { await api.SaveSettings(s); S.settings = s; } catch (err) { toast(String(err), true); e.target.checked = !e.target.checked; }
});

// ---------- import ----------
function reportImport(r) {
  const parts = [];
  if (r.added) parts.push(t("imported", r.added));
  if (r.updated) parts.push(t("updated", r.updated));
  if (r.subscriptions) parts.push(t("subsAdded", r.subscriptions));
  if (r.skipped) parts.push(t("skipped", r.skipped));
  if (!r.added && !r.updated && !r.subscriptions) {
    toast(t("nothing") + (r.skipped ? " — " + t("skipped", r.skipped) : ""), true);
  } else {
    toast(parts.join(" · "));
    if (r.firstId) select(r.firstId);
  }
}

async function importText(text) {
  try { reportImport(await api.ImportText(text)); } catch (err) { toast(String(err), true); }
}

$("#btnPaste").addEventListener("click", async () => {
  try { reportImport(await api.ImportClipboard()); } catch (err) { toast(String(err), true); }
});

// Ctrl+V anywhere outside text fields imports.
document.addEventListener("paste", (e) => {
  const tag = e.target.tagName;
  if (tag === "INPUT" || tag === "TEXTAREA" || document.querySelector("dialog[open]")) return;
  const text = e.clipboardData?.getData("text") ?? "";
  e.preventDefault();
  importText(text);
});

document.addEventListener("keydown", (e) => {
  if (document.querySelector("dialog[open]")) return;
  const i = S.profiles.findIndex((p) => p.id === S.selected);
  if (e.key === "ArrowDown" || e.key === "ArrowUp") {
    e.preventDefault();
    const n = S.profiles[Math.max(0, Math.min(S.profiles.length - 1, i + (e.key === "ArrowDown" ? 1 : -1)))];
    if (n) { select(n.id); document.querySelector(`.item[data-id="${n.id}"]`)?.scrollIntoView({ block: "nearest" }); }
  } else if (e.key === "Enter" && S.selected) {
    connect(S.selected);
  } else if (e.key === "Delete" && S.selected) {
    document.querySelector(`.item[data-id="${S.selected}"] [data-act=del]`)?.click();
  } else if (e.key === "F2" && S.selected) {
    openEdit(S.selected);
  }
});

// ---------- edit dialog ----------
let editingId = "";
async function openEdit(id) {
  const f = $("#formEdit");
  f.reset();
  $("#editError").textContent = "";
  editingId = id || "";
  $("#editTitle").textContent = id ? t("editConfig") : t("newConfig");
  $("#btnForgetKey").classList.toggle("hidden", !id || !S.profiles.find((p) => p.id === id)?.hostKey);
  if (id) {
    try {
      const p = await api.GetProfile(id);
      for (const k of ["name", "host", "port", "username", "password", "privateKey", "hostKey", "udpgwPort"]) f.elements[k].value = p[k] ?? "";
    } catch (err) { return toast(String(err), true); }
  }
  $("#dlgEdit").showModal();
}
$("#btnAdd").addEventListener("click", () => openEdit(""));
$("#formEdit").addEventListener("submit", async (e) => {
  if (e.submitter?.value !== "ok") return;
  e.preventDefault();
  const f = e.target.elements;
  const p = {
    id: editingId, name: f.name.value, host: f.host.value, port: +f.port.value, username: f.username.value,
    password: f.password.value, privateKey: f.privateKey.value, hostKey: f.hostKey.value, udpgwPort: +f.udpgwPort.value || 0,
  };
  try {
    const id = await api.SaveProfile(p);
    $("#dlgEdit").close();
    select(id);
  } catch (err) { $("#editError").textContent = String(err); }
});
$("#btnForgetKey").addEventListener("click", async () => {
  await api.ForgetHostKey(editingId);
  $("#btnForgetKey").classList.add("hidden");
  toast(t("saved"));
});

// ---------- settings dialog ----------
$("#btnSettings").addEventListener("click", () => {
  const f = $("#formSettings").elements, s = S.settings;
  f.socksPort.value = s.socksPort; f.httpPort.value = s.httpPort;
  for (const k of ["systemProxy", "connectOnStart", "startWithWindows", "tunMode"]) f[k].checked = !!s[k];
  f.bypassList.value = (s.bypassList || []).join("\n");
  $("#settingsError").textContent = "";
  $("#dlgSettings").showModal();
});
$("#formSettings").addEventListener("submit", async (e) => {
  if (e.submitter?.value !== "ok") return;
  e.preventDefault();
  const f = e.target.elements;
  const s = {
    ...S.settings,
    socksPort: +f.socksPort.value, httpPort: +f.httpPort.value,
    systemProxy: f.systemProxy.checked, connectOnStart: f.connectOnStart.checked,
    startWithWindows: f.startWithWindows.checked, tunMode: f.tunMode.checked,
    bypassList: f.bypassList.value.split(/\r?\n/).map((x) => x.trim()).filter(Boolean),
  };
  try {
    await api.SaveSettings(s);
    const tunTurnedOn = s.tunMode && !S.settings.tunMode;
    S.settings = s;
    $("#dlgSettings").close();
    renderStatus();
    toast(tunTurnedOn && !S.isAdmin ? t("tunNeedsAdmin") : t("saved"));
  } catch (err) { $("#settingsError").textContent = String(err); }
});

async function saveUiPref(patch) {
  S.settings = { ...S.settings, ...patch };
  try { await api.SaveSettings(S.settings); } catch (_) { /* cosmetic */ }
}
$("#btnTheme").addEventListener("click", () => { saveUiPref({ theme: S.settings.theme === "light" ? "dark" : "light" }); applyTheme(); });
$("#btnLang").addEventListener("click", () => { lang = lang === "fa" ? "en" : "fa"; saveUiPref({ language: lang }); applyLang(); renderSubs(); });

// ---------- subscriptions ----------
function renderSubs() {
  const box = $("#subsList");
  if (!box) return;
  box.innerHTML = S.subs.map((s) => {
    const n = S.profiles.filter((p) => p.subId === s.id).length;
    const used = (s.upload || 0) + (s.download || 0);
    const pct = s.total ? Math.min(100, (used / s.total) * 100) : 0;
    const exp = s.expire ? new Date(s.expire * 1000).toLocaleDateString(lang === "fa" ? "fa-IR" : "en-GB") : "";
    const info = [t("configsN", n)];
    if (s.total || used) info.push(`${t("used")}: ${fmtBytes(used)} / ${s.total ? fmtBytes(s.total) : t("unlimited")}`);
    if (exp) info.push(`${t("expire")}: ${exp}`);
    return `<div class="sub" data-id="${esc(s.id)}">
      <div><b>${esc(s.name)}</b><div class="url">${esc(s.url)}</div><div class="info">${info.join(" · ")}</div></div>
      <div class="row"><button type="button" class="btn small" data-sub="update">${t("update")}</button>
      <button type="button" class="btn small ghost" data-sub="remove">${t("remove")}</button></div>
      ${s.total ? `<div class="bar"><i style="width:${pct}%"></i></div>` : ""}
    </div>`;
  }).join("");
}
$("#btnSubs").addEventListener("click", () => { renderSubs(); $("#subsError").textContent = ""; $("#dlgSubs").showModal(); });
$("#btnSubAdd").addEventListener("click", async () => {
  const inp = $("#formSubs").elements.url;
  const url = inp.value.trim();
  if (!url) return;
  $("#subsError").textContent = t("testing");
  try { await api.AddSubscription(url); inp.value = ""; $("#subsError").textContent = ""; }
  catch (err) { $("#subsError").textContent = String(err); }
});
$("#subsList").addEventListener("click", async (e) => {
  const b = e.target.closest("[data-sub]");
  if (!b) return;
  const id = b.closest(".sub").dataset.id;
  b.disabled = true;
  try {
    if (b.dataset.sub === "update") await api.UpdateSubscription(id);
    else await api.RemoveSubscription(id);
    $("#subsError").textContent = "";
  } catch (err) { $("#subsError").textContent = String(err); }
  b.disabled = false;
});

// ---------- toolbar ----------
$("#btnTestAll").addEventListener("click", async () => {
  S.profiles.forEach((p) => S.testing.add(p.id));
  renderList();
  try { await api.TestAllLatency(); } finally { S.testing.clear(); renderList(); }
});
$("#btnSort").addEventListener("click", () => api.SortByLatency());

// ---------- logs ----------
const logsEl = $("#logs");
function appendLog(line) {
  const atBottom = logsEl.scrollTop + logsEl.clientHeight >= logsEl.scrollHeight - 4;
  logsEl.textContent += (logsEl.textContent ? "\n" : "") + line;
  const lines = logsEl.textContent.split("\n");
  if (lines.length > 500) logsEl.textContent = lines.slice(-500).join("\n");
  if (atBottom) logsEl.scrollTop = logsEl.scrollHeight;
}
$("#btnCopyLogs").addEventListener("click", async () => {
  const text = (await api.GetLogs()).join("\n");
  if (window.runtime) await window.runtime.ClipboardSetText(text);
  else await navigator.clipboard?.writeText(text);
  toast(t("copied"));
});
$("#btnLogsToggle").addEventListener("click", () => {
  const p = $("#logsPane");
  p.classList.toggle("collapsed");
  $("#logsArrow").textContent = p.classList.contains("collapsed") ? "▸" : "▾";
});

// ---------- boot ----------
on("profiles", (ps) => { S.profiles = ps || []; if (S.selected && !S.profiles.some((p) => p.id === S.selected)) S.selected = ""; renderList(); renderStatus(); });
on("subscriptions", (ss) => { S.subs = ss || []; renderSubs(); renderList(); });
on("status", (s) => { const prev = S.status.state; S.status = s; renderStatus(); if (prev !== s.state) renderList(); });
on("log", appendLog);

(async function boot() {
  const snap = await api.Init();
  S.profiles = snap.profiles || [];
  S.subs = snap.subscriptions || [];
  S.settings = snap.settings;
  S.status = snap.status;
  S.selected = snap.settings.lastSelected || "";
  S.isAdmin = !!snap.isAdmin;
  lang = snap.settings.language === "en" ? "en" : "fa";
  logsEl.textContent = (snap.logs || []).join("\n");
  logsEl.scrollTop = logsEl.scrollHeight;
  applyTheme();
  applyLang();
})();

// ---------- mock backend for previewing the UI in a plain browser ----------
function mockOn(ev, fn) { (mockOn.h ??= {})[ev] = fn; }
function mockApi() {
  const emit = (ev, d) => mockOn.h?.[ev]?.(d);
  const st = { socksPort: 10808, httpPort: 10809, systemProxy: true, language: "fa", theme: "dark", bypassList: ["localhost"] };
  let profiles = [
    { id: "a1", name: "SSH | test-user", host: "ssh.example.com", port: 7777, username: "sv_1a2b3c4d", latencyMs: 182, hostKey: true },
    { id: "b2", name: "سرور آلمان ۱", host: "de1.example.net", port: 22, username: "user42", latencyMs: 640 },
    { id: "c3", name: "Netherlands – a very long configuration name that should be truncated nicely", host: "203.0.113.77", port: 2222, username: "nl", latencyMs: -1, subId: "s1" },
  ];
  const subs = [{ id: "s1", name: "my-sub", url: "https://sub.example.com/abc", upload: 2e9, download: 9e9, total: 50e9, expire: 1798000000 }];
  let status = { state: "disconnected" };
  return {
    Init: async () => ({ profiles, subscriptions: subs, settings: st, status, logs: ["12:00:00 SSHTunnel started (preview)"] }),
    SelectProfile: async () => {}, TestLatency: async () => 100, TestAllLatency: async () => {}, SortByLatency: async () => {},
    DeleteProfile: async (id) => { profiles = profiles.filter((p) => p.id !== id); emit("profiles", profiles); },
    GetProfile: async (id) => ({ ...profiles.find((p) => p.id === id), password: "x", udpgwPort: 7300 }),
    SaveProfile: async (p) => p.id || "new", ForgetHostKey: async () => {},
    SaveSettings: async () => {}, GetLogs: async () => ["log"],
    ImportText: async () => ({ added: 1, updated: 0, skipped: 2 }), ImportClipboard: async () => ({ added: 0, skipped: 1 }),
    AddSubscription: async () => {}, UpdateSubscription: async () => {}, RemoveSubscription: async () => {},
    Connect: async (id) => {
      const p = profiles.find((x) => x.id === id);
      status = { state: "connected", profileId: id, profileName: p.name, uptimeSec: 3725, up: 1.2e6, down: 48.3e6, upSpeed: 12000, downSpeed: 830000, latencyMs: 174, socksAddr: "127.0.0.1:10808", httpAddr: "127.0.0.1:10809", udpActive: true };
      emit("status", status);
    },
    Disconnect: async () => { status = { state: "disconnected" }; emit("status", status); },
  };
}
