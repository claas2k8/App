// Docvault: upload documents to your own website and open them anywhere.
// Needs env vars on Vercel: APP_PASSWORD, and BLOB_READ_WRITE_TOKEN (added when you connect a Blob store).
const express = require("express");
const crypto = require("crypto");
const { list, del } = require("@vercel/blob");
const { handleUpload } = require("@vercel/blob/client");

const app = express();
app.use(express.json());

const sessionToken = () =>
  crypto.createHash("sha256").update("docvault:" + (process.env.APP_PASSWORD || "")).digest("hex");

function authed(req) {
  if (!process.env.APP_PASSWORD) return false;
  const m = /(?:^|;\s*)dv=([a-f0-9]+)/.exec(req.headers.cookie || "");
  return !!m && m[1] === sessionToken();
}
const guard = (req, res, next) => (authed(req) ? next() : res.status(401).json({ error: "Not signed in" }));

app.post("/api/login", (req, res) => {
  const pw = (req.body && req.body.password) || "";
  if (!process.env.APP_PASSWORD || pw !== process.env.APP_PASSWORD) {
    return res.status(401).json({ error: "Wrong password" });
  }
  res.setHeader("Set-Cookie", "dv=" + sessionToken() + "; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=7776000");
  res.json({ ok: true });
});

app.get("/api/files", guard, async (req, res) => {
  const { blobs } = await list({ limit: 1000 });
  const files = blobs
    .map((b) => ({
      url: b.url,
      name: b.pathname.split("/").slice(1).join("/") || b.pathname,
      size: b.size,
      uploadedAt: b.uploadedAt,
    }))
    .sort((a, b) => new Date(b.uploadedAt) - new Date(a.uploadedAt));
  res.json({ files });
});

app.delete("/api/files", guard, async (req, res) => {
  await del(req.body.url);
  res.json({ ok: true });
});

// Files go straight from the browser to Blob storage, so big files work.
app.post("/api/upload", async (req, res) => {
  try {
    const json = await handleUpload({
      body: req.body,
      request: req,
      onBeforeGenerateToken: async () => {
        if (!authed(req)) throw new Error("Not signed in");
        return { addRandomSuffix: false, maximumSizeInBytes: 500 * 1024 * 1024 };
      },
      onUploadCompleted: async () => {},
    });
    res.json(json);
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

const PAGE = `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Docvault</title>
<style>
:root{--bg:#eef1ee;--surface:#fff;--ink:#1d2b26;--muted:#66746d;--line:#d3dad5;--accent:#1f6f5c;--accent-ink:#fff;--danger:#b3372c;color-scheme:light dark}
@media (prefers-color-scheme:dark){:root{--bg:#121816;--surface:#1a231f;--ink:#e6ede9;--muted:#8fa097;--line:#2c3a34;--accent:#5fc2a5;--accent-ink:#0c1512;--danger:#ef8a7e}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.5 Georgia,"Iowan Old Style",serif}
button,input{font:inherit;color:inherit}
main{max-width:760px;margin:0 auto;padding:32px 20px 64px}
h1{font-size:2rem;margin:0 0 4px;letter-spacing:-.01em}
.sub{color:var(--muted);margin:0 0 24px}
.drop{display:block;position:relative;border:2px dashed var(--line);border-radius:6px;padding:28px 16px;text-align:center;background:var(--surface);cursor:pointer}
.drop.over,.drop:focus-within{border-color:var(--accent)}
.drop input{position:absolute;opacity:0;width:1px;height:1px}
.drop b{color:var(--accent)}
.bar{display:flex;gap:12px;margin:24px 0 8px}
input.t{width:100%;padding:10px 12px;border:1px solid var(--line);border-radius:6px;background:var(--surface);margin:12px 0}
.bar input.t{flex:1;margin:0}
.row{display:flex;align-items:center;gap:12px;padding:12px 4px;border-bottom:1px solid var(--line)}
.row a{flex:1;min-width:0;color:var(--ink);text-decoration:none;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.row a:hover,.row a:focus-visible{color:var(--accent);text-decoration:underline}
.meta{color:var(--muted);font-size:.85rem;white-space:nowrap}
.x{background:none;border:0;color:var(--muted);cursor:pointer;padding:6px 8px;border-radius:4px}
.x:hover,.x:focus-visible{color:var(--danger)}
.btn{background:var(--accent);color:var(--accent-ink);border:0;border-radius:6px;padding:10px 18px;cursor:pointer}
.msg{color:var(--muted)}.err{color:var(--danger)}
#login{max-width:360px;margin:8vh auto 0}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
[hidden]{display:none!important}
</style></head>
<body><main>
<h1>Docvault</h1>
<p class="sub">Your documents, on any device.</p>

<form id="login" hidden>
  <p>Enter your password to open your documents.</p>
  <input class="t" id="pw" type="password" placeholder="Password" autocomplete="current-password">
  <button class="btn">Open</button>
  <p class="err" id="loginErr" role="alert"></p>
</form>

<section id="app" hidden>
  <label class="drop" id="drop"><input type="file" id="file" multiple><b>Choose files</b> or drop them here</label>
  <p class="msg" id="status" role="status"></p>
  <div class="bar"><input class="t" id="q" placeholder="Search by name"><button class="btn" id="refresh">Refresh</button></div>
  <div id="list"></div>
</section>
</main>

<script type="module">
import { upload } from "https://esm.sh/@vercel/blob@1/client";
const $ = (id) => document.getElementById(id);
let files = [];
const fmt = (n) => n > 1e6 ? (n / 1e6).toFixed(1) + " MB" : Math.max(1, Math.round(n / 1e3)) + " KB";

async function load() {
  const r = await fetch("/api/files");
  if (r.status === 401) { $("login").hidden = false; $("app").hidden = true; return; }
  $("login").hidden = true; $("app").hidden = false;
  files = (await r.json()).files;
  render();
}

function render() {
  const q = $("q").value.toLowerCase();
  const list = $("list");
  list.textContent = "";
  if (!files.length) { list.innerHTML = '<p class="msg">No documents yet. Upload your first file above.</p>'; return; }
  files.filter((f) => f.name.toLowerCase().includes(q)).forEach((f) => {
    const row = document.createElement("div"); row.className = "row";
    const a = document.createElement("a"); a.href = f.url; a.target = "_blank"; a.rel = "noreferrer"; a.textContent = f.name;
    const m = document.createElement("span"); m.className = "meta";
    m.textContent = fmt(f.size) + " · " + new Date(f.uploadedAt).toLocaleDateString();
    const x = document.createElement("button"); x.className = "x"; x.textContent = "Delete";
    x.setAttribute("aria-label", "Delete " + f.name);
    x.onclick = async () => {
      if (!confirm("Delete " + f.name + "?")) return;
      await fetch("/api/files", { method: "DELETE", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url: f.url }) });
      load();
    };
    row.append(a, m, x); list.append(row);
  });
}

async function send(list) {
  const items = [...list];
  for (let i = 0; i < items.length; i++) {
    const f = items[i];
    $("status").textContent = "Uploading " + f.name + " (" + (i + 1) + " of " + items.length + ")…";
    try {
      await upload(crypto.randomUUID() + "/" + f.name, f, { access: "public", handleUploadUrl: "/api/upload" });
    } catch (e) {
      $("status").textContent = "Could not upload " + f.name + ": " + e.message; return;
    }
  }
  $("status").textContent = "";
  load();
}

$("login").onsubmit = async (e) => {
  e.preventDefault();
  const r = await fetch("/api/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ password: $("pw").value }) });
  if (r.ok) { $("pw").value = ""; $("loginErr").textContent = ""; load(); }
  else $("loginErr").textContent = "That password is not right. Try again.";
};
$("q").oninput = render;
$("refresh").onclick = load;
$("file").onchange = (e) => { send(e.target.files); e.target.value = ""; };
const drop = $("drop");
drop.ondragover = (e) => { e.preventDefault(); drop.classList.add("over"); };
drop.ondragleave = () => drop.classList.remove("over");
drop.ondrop = (e) => { e.preventDefault(); drop.classList.remove("over"); send(e.dataTransfer.files); };
load();
</script></body></html>`;

app.get("/", (req, res) => res.type("html").send(PAGE));

module.exports = app;
if (require.main === module) app.listen(3000, () => console.log("http://localhost:3000"));
