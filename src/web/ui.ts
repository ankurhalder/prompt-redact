export const SERVE_PAGE = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>prompt-redact inspector</title>
<style>
  :root { color-scheme: dark; --bg: #0b1020; --card: #121a2f; --fg: #e6ecf7; --muted: #93a3c0; --accent: #38bdf8; --ok: #34d399; --border: #233152; }
  * { box-sizing: border-box; }
  body { margin: 0; font-family: ui-sans-serif, system-ui, -apple-system, sans-serif; background: var(--bg); color: var(--fg); padding: 24px; }
  main { max-width: 1080px; margin: 0 auto; display: grid; gap: 16px; }
  header { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; }
  h1 { margin: 0; font-size: 20px; }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 16px; display: grid; gap: 12px; }
  .row { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }
  textarea, input, select { width: 100%; background: #080d1a; color: var(--fg); border: 1px solid var(--border); border-radius: 8px; padding: 10px; font-family: ui-monospace, SFMono-Regular, monospace; font-size: 13px; }
  textarea { min-height: 140px; resize: vertical; }
  button { background: var(--accent); color: #051320; border: 0; border-radius: 8px; padding: 8px 14px; font-weight: 600; cursor: pointer; }
  button.secondary { background: #1f2b48; color: var(--fg); }
  pre { margin: 0; background: #080d1a; border: 1px solid var(--border); border-radius: 8px; padding: 12px; overflow: auto; font-size: 12px; white-space: pre-wrap; }
  .grid2 { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 16px; }
  .stat { font-size: 13px; color: var(--muted); }
  .stat strong { color: var(--ok); }
</style>
</head>
<body>
<main>
  <header>
    <h1>prompt-redact inspector</h1>
    <div class="row" style="min-width: 320px;">
      <input id="token" type="password" placeholder="Bearer token (from CLI output)" />
      <button class="secondary" id="saveToken">Save</button>
    </div>
  </header>

  <section class="card">
    <div class="row">
      <button id="btnRedact">Tokenize Outbound</button>
      <button id="btnRehydrate" class="secondary">Rehydrate Inbound</button>
      <button id="btnSse" class="secondary">Simulate Split SSE</button>
      <span id="status" class="stat"></span>
    </div>
    <div class="grid2">
      <div>
        <label for="input">Input Prompt / JSON / SSE</label>
        <textarea id="input" placeholder="Paste prompt, JSON payload, or API key..."></textarea>
      </div>
      <div>
        <label for="output">Output</label>
        <pre id="output">(ready)</pre>
      </div>
    </div>
  </section>

  <section class="card">
    <div class="row">
      <strong>Live Session Audit (Zero Plaintext)</strong>
      <button id="btnAudit" class="secondary">Refresh</button>
    </div>
    <pre id="audit">(no events yet)</pre>
  </section>
</main>
<script>
const tokenInput = document.getElementById("token");
const inputEl = document.getElementById("input");
const outputEl = document.getElementById("output");
const auditEl = document.getElementById("audit");
const statusEl = document.getElementById("status");
tokenInput.value = sessionStorage.getItem("pr_token") || "";
document.getElementById("saveToken").onclick = () => {
  sessionStorage.setItem("pr_token", tokenInput.value.trim());
  statusEl.textContent = "Token saved for this tab";
};
async function api(path, body) {
  const tok = tokenInput.value.trim();
  const headers = { "content-type": "application/json" };
  if (tok) headers["authorization"] = "Bearer " + tok;
  const res = await fetch(path, {
    method: body ? "POST" : "GET",
    headers,
    body: body ? JSON.stringify(body) : undefined
  });
  return await res.json();
}
async function refreshAudit() {
  const data = await api("/api/audit");
  auditEl.textContent = JSON.stringify(data, null, 2);
}
document.getElementById("btnRedact").onclick = async () => {
  const data = await api("/api/redact", { text: inputEl.value });
  outputEl.textContent = data.error ? JSON.stringify(data, null, 2) : data.redacted;
  statusEl.textContent = data.hits !== undefined ? "hits: " + data.hits : "";
  await refreshAudit();
};
document.getElementById("btnRehydrate").onclick = async () => {
  const data = await api("/api/rehydrate", { text: inputEl.value });
  outputEl.textContent = data.error ? JSON.stringify(data, null, 2) : data.text;
  statusEl.textContent = "rehydrated";
};
document.getElementById("btnSse").onclick = async () => {
  const data = await api("/api/sse-simulate", { text: inputEl.value });
  outputEl.textContent = JSON.stringify(data, null, 2);
  await refreshAudit();
};
document.getElementById("btnAudit").onclick = refreshAudit;
</script>
</body>
</html>
`;
