import express from "express";
import { chromium, devices } from "playwright";

const app = express();
const PORT = process.env.PORT || 8080;

/* CORS */
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", process.env.CORS_ORIGIN || "*");
  res.setHeader("Access-Control-Allow-Methods", "GET");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  next();
});

/* Anti-SSRF simple */
function isForbiddenHost(u) {
  try {
    const url = new URL(u);
    const h = url.hostname.toLowerCase();
    if (h === "localhost" || h === "127.0.0.1" || h.endsWith(".local")) return true;
    return false;
  } catch { return true; }
}

/* -------- Navigateur partagé, avec auto-recreate -------- */
let browser = null;
let launching = null;

async function ensureBrowser() {
  if (browser) return browser;
  if (launching) return launching;

  launching = chromium.launch({
    headless: true,
    args: [
      "--no-sandbox",
      "--disable-dev-shm-usage",
      "--disable-gpu",
      "--single-process",
      "--no-zygote",
    ],
  }).then(b => {
    browser = b;
    // si crash/déconnexion, on le recréera au prochain appel
    browser.on("disconnected", () => (browser = null));
    launching = null;
    return browser;
  }).catch(err => {
    launching = null;
    throw err;
  });

  return launching;
}

/* -------- Petite file: 1 analyse à la fois (anti pics RAM) -------- */
const queue = [];
let running = 0;
const MAX_CONCURRENCY = 1;
function enqueue(task) {
  return new Promise((resolve, reject) => {
    queue.push({ task, resolve, reject });
    drain();
  });
}
async function drain() {
  if (running >= MAX_CONCURRENCY || queue.length === 0) return;
  const { task, resolve, reject } = queue.shift();
  running++;
  task().then(resolve).catch(reject).finally(() => {
    running--;
    drain();
  });
}

/* -------- Lecture perf (retry si renavigation) -------- */
async function readPerfWithRetry(page) {
  const read = () => page.evaluate(() => {
    const nav = performance.getEntriesByType("navigation")[0];
    const res = performance.getEntriesByType("resource") || [];
    let bytes = 0;
    if (nav && nav.transferSize) bytes += nav.transferSize;
    for (const r of res) bytes += (r.transferSize || r.encodedBodySize || 0);
    const raw = nav ? nav.duration / 1000 : 0;
    const duration_s = Math.max(raw, 5);
    return { mb: bytes / (1024 * 1024), requests: (res?.length || 0) + 1, duration_s };
  });

  try { return await read(); }
  catch (e) {
    if (/Execution context was destroyed/i.test(e?.message || "")) {
      await page.waitForLoadState("domcontentloaded", { timeout: 8000 }).catch(()=>{});
      await page.waitForTimeout(800);
      return await read();
    }
    throw e;
  }
}

/* -------- Une passe (mobile), avec ressources lourdes bloquées -------- */
async function analyzeOnce(url) {
  const b = await ensureBrowser();
  const mobile = devices["Pixel 5"];

  const context = await b.newContext({
    ...mobile,
    ignoreHTTPSErrors: true,
    viewport: mobile?.viewport || { width: 1080, height: 1920 },
    userAgent: mobile?.userAgent ||
      "Mozilla/5.0 (Linux; Android 12; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36",
  });

  // Bloquer images/vidéos/polices pour réduire RAM/temps
  await context.route("**/*", (route) => {
    const req = route.request();
    const type = req.resourceType();
    if (["image", "media", "font"].includes(type)) return route.abort(); // on mesure le transfert réseau via perf, pas besoin d’afficher
    route.continue();
  });

  context.setDefaultNavigationTimeout(30000);
  const page = await context.newPage();

  try {
    const resp = await page.goto(url, { waitUntil: "commit", timeout: 30000 });
    if (!resp) throw new Error("No response");

    await page.waitForLoadState("domcontentloaded", { timeout: 15000 }).catch(()=>{});
    await page.waitForTimeout(800);

    const data = await readPerfWithRetry(page);
    return data;
  } finally {
    await page.close().catch(()=>{});
    await context.close().catch(()=>{});
  }
}

/* -------- Endpoint /analyze -------- */
app.get("/analyze", async (req, res) => {
  const url = req.query.url;
  if (!url) return res.status(400).json({ error: "Missing url param" });
  if (isForbiddenHost(url)) return res.status(400).json({ error: "Forbidden host" });

  enqueue(async () => {
    try {
      const v = await analyzeOnce(url);

      // Hypothèses
      const assumptions = {
        mobile_share: 1.0,                  // 100% mobile puisque 1 seule passe
        network_wh_per_mb_mobile: 0.08,
        network_wh_per_mb_fixed: 0.04,      // pas utilisé ici
        client_power_w_mobile: 2,
        client_power_w_desktop: 20,         // pas utilisé ici
        server_wh_per_view: 0.03,
        grid_g_per_kwh: 45
      };

      const mb = v.mb;
      const reqs = v.requests;
      const dur = v.duration_s;

      const network_wh = mb * assumptions.network_wh_per_mb_mobile;
      const client_wh  = assumptions.client_power_w_mobile * (dur / 3600);
      const server_wh  = assumptions.server_wh_per_view;

      const total_kwh = (network_wh + client_wh + server_wh) / 1000;
      const co2_g     = total_kwh * assumptions.grid_g_per_kwh;

      res.json({
        url,
        page_bytes_mb: Number(mb.toFixed(3)),
        requests: reqs,
        network_wh: Number(network_wh.toFixed(6)),
        client_wh: Number(client_wh.toFixed(6)),
        server_wh: Number(server_wh.toFixed(6)),
        co2_g: Number(co2_g.toFixed(6)),
        assumptions
      });
    } catch (e) {
      // si le navigateur est tombé, on le recréera à la prochaine
      browser = null;
      console.error("[/analyze] error:", e.message);
      res.status(500).json({ error: e.message || "Analyze failed" });
    }
  }).catch(e => {
    console.error("[/analyze] queue error:", e);
    res.status(500).json({ error: "Queue error" });
  });
});

/* Routes de test */
app.get("/", (req, res) => res.send("OK"));
app.get("/ping", (req, res) => res.json({ ok: true, time: Date.now() }));

/* Shutdown propre */
async function shutdown() { try { await browser?.close(); } catch {} process.exit(0); }
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);

app.listen(PORT, () => console.log("Nooki CO2 analyzer on :" + PORT));
