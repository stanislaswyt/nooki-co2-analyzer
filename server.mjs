import express from "express";
import { chromium, devices } from "playwright";

const app = express();
const PORT = process.env.PORT || 8080;

/* -------------------- Config -------------------- */
const CONFIG = {
  GOTO_TIMEOUT_MS:   +process.env.GOTO_TIMEOUT_MS   || 45_000,
  DOM_TIMEOUT_MS:    +process.env.DOM_TIMEOUT_MS    || 25_000,
  GLOBAL_TIMEOUT_MS: +process.env.GLOBAL_TIMEOUT_MS || 120_000,
  CACHE_TTL_MS:      +process.env.CACHE_TTL_MS      || 300_000, // 5 min
  RELAUNCH_EVERY:    +process.env.RELAUNCH_EVERY    || 60,
  MAX_CONCURRENCY:   +process.env.MAX_CONCURRENCY   || 1
};

/* -------------------- CORS -------------------- */
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", process.env.CORS_ORIGIN || "*");
  res.setHeader("Access-Control-Allow-Methods", "GET");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  next();
});

/* -------------------- Anti-SSRF simple -------------------- */
function isForbiddenHost(u) {
  try {
    const url = new URL(u);
    const h = url.hostname.toLowerCase();
    if (h === "localhost" || h === "127.0.0.1" || h.endsWith(".local")) return true;
    return false;
  } catch { return true; }
}

/* -------------------- Navigateur partagé -------------------- */
let browser = null;
let launching = null;
let analysesSinceLaunch = 0;

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
      "--disable-webgl",
      "--disable-extensions",
    ],
  }).then(b => {
    browser = b;
    analysesSinceLaunch = 0;
    b.on("disconnected", () => (browser = null));
    launching = null;
    return b;
  }).catch(err => {
    launching = null;
    throw err;
  });

  return launching;
}

/* -------------------- File d’attente avec anti-doublon -------------------- */
const queue = [];
let running = 0;
const pendingUrls = new Map(); // url -> [resolveFns]
const cache = new Map(); // url -> { time, result }

function enqueue(url, task) {
  return new Promise((resolve, reject) => {
    // 1. Si en cache et frais → renvoie direct
    const cached = cache.get(url);
    if (cached && Date.now() - cached.time < CONFIG.CACHE_TTL_MS) {
      return resolve(cached.result);
    }

    // 2. Si déjà en cours → on s'abonne au résultat
    if (pendingUrls.has(url)) {
      pendingUrls.get(url).push({ resolve, reject });
      return;
    }

    // 3. Sinon, première demande pour cette URL → créer la liste d'attente
    pendingUrls.set(url, [{ resolve, reject }]);
    queue.push({ url, task });
    drain();
  });
}

async function drain() {
  if (running >= CONFIG.MAX_CONCURRENCY || queue.length === 0) return;
  const { url, task } = queue.shift();
  running++;

  try {
    const result = await task();
    cache.set(url, { time: Date.now(), result });

    // Résoudre toutes les promesses liées à cette URL
    pendingUrls.get(url).forEach(({ resolve }) => resolve(result));
  } catch (err) {
    pendingUrls.get(url).forEach(({ reject }) => reject(err));
  } finally {
    pendingUrls.delete(url);
    running--;
    drain();
  }
}

app.get("/queue", (_req, res) => {
  res.json({ waiting: Math.max(0, queue.length), running, capacity: CONFIG.MAX_CONCURRENCY });
});

/* -------------------- Utils -------------------- */
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

async function withTimeout(promise, ms, label = "timeout") {
  let to;
  const timer = new Promise((_, rej) => (to = setTimeout(() => rej(new Error(label)), ms)));
  try { return await Promise.race([promise, timer]); }
  finally { clearTimeout(to); }
}

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
      await page.waitForLoadState("domcontentloaded", { timeout: 8_000 }).catch(()=>{});
      await sleep(800);
      return await read();
    }
    throw e;
  }
}

/* -------------------- Analyse -------------------- */
async function analyzeOnce(url, fresh = false) {
  if (fresh || analysesSinceLaunch >= CONFIG.RELAUNCH_EVERY) {
    try { await browser?.close(); } catch {}
    browser = null;
  }

  const b = await ensureBrowser();

  // 1) Essaie d'abord en Desktop (certains sites filtrent le mobile headless)
  const desktopUA = {
    userAgent:
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    viewport: { width: 1366, height: 850 },
    deviceScaleFactor: 1,
    isMobile: false,
    hasTouch: false,
    locale: "fr-FR",
  };

  let context, page;
  try {
    context = await b.newContext({
      ...desktopUA,
      ignoreHTTPSErrors: true,
      extraHTTPHeaders: {
        "Accept-Language": "fr-FR,fr;q=0.9,en;q=0.8",
        "Upgrade-Insecure-Requests": "1",
      },
    });

    // Bloque juste les polices et médias lourds (on laisse passer les images si besoin)
    await context.route("**/*", (route) => {
      const t = route.request().resourceType();
      if (t === "font" || t === "media") return route.abort();
      route.continue();
    });

    context.setDefaultNavigationTimeout(CONFIG.GOTO_TIMEOUT_MS);
    page = await context.newPage();

    // 2) Aller directement jusqu’à DOMContentLoaded (bien accepté par bcp de CMS/pare-feux)
    let resp = await page.goto(url, { waitUntil: "domcontentloaded", timeout: CONFIG.GOTO_TIMEOUT_MS });
    if (!resp) throw new Error("No response");

    // Fallback léger : si le DOM est vraiment tardif, on laisse 1,2 s pour les scripts init
    await sleep(1200);

    // 3) Lecture des perfs (avec retry si renavigation)
    const data = await readPerfWithRetry(page);
    analysesSinceLaunch++;
    return data;

  } catch (e) {
    // Si ça sent le filtrage desktop, on retente en "Pixel 5" mobile
    const msg = String(e?.message || e);
    if (!fresh && /blocked|forbidden|closed|context was destroyed|navigation timeout/i.test(msg)) {
      try { await page?.close(); } catch {}
      try { await context?.close(); } catch {}

      const mobile = devices["Pixel 5"];
      context = await b.newContext({
        ...mobile,
        ignoreHTTPSErrors: true,
        locale: "fr-FR",
        extraHTTPHeaders: { "Accept-Language": "fr-FR,fr;q=0.9,en;q=0.8" },
      });
      await context.route("**/*", (route) => {
        const t = route.request().resourceType();
        if (t === "font" || t === "media") return route.abort();
        route.continue();
      });
      page = await context.newPage();
      await page.goto(url, { waitUntil: "domcontentloaded", timeout: CONFIG.GOTO_TIMEOUT_MS });
      await sleep(1200);
      const data = await readPerfWithRetry(page);
      analysesSinceLaunch++;
      return data;
    }
    // Sinon : vrai échec
    throw e;

  } finally {
    try { await page?.close(); } catch {}
    try { await context?.close(); } catch {}
  }
}

/* -------------------- Endpoint /analyze -------------------- */
app.get("/analyze", async (req, res) => {
  const url = req.query.url;
  if (!url) return res.status(400).json({ error: "Missing url param" });
  if (isForbiddenHost(url)) return res.status(400).json({ error: "Forbidden host" });

  try {
    const result = await enqueue(url, async () => {
      const v = await withTimeout(analyzeOnce(url), CONFIG.GLOBAL_TIMEOUT_MS, "Global analyze timeout");

      const assumptions = {
        mobile_share: 1.0,
        network_wh_per_mb_mobile: 0.08,
        network_wh_per_mb_fixed: 0.04,
        client_power_w_mobile: 2,
        client_power_w_desktop: 20,
        server_wh_per_view: 0.03,
        grid_g_per_kwh: 45,
      };

      const mb = v.mb;
      const reqs = v.requests;
      const dur = v.duration_s;

      const network_wh = mb * assumptions.network_wh_per_mb_mobile;
      const client_wh  = assumptions.client_power_w_mobile * (dur / 3600);
      const server_wh  = assumptions.server_wh_per_view;

      const total_kwh = (network_wh + client_wh + server_wh) / 1000;
      const co2_g     = total_kwh * assumptions.grid_g_per_kwh;

      return {
        url,
        page_bytes_mb: Number(mb.toFixed(3)),
        requests: reqs,
        network_wh: Number(network_wh.toFixed(6)),
        client_wh: Number(client_wh.toFixed(6)),
        server_wh: Number(server_wh.toFixed(6)),
        co2_g: Number(co2_g.toFixed(6)),
        assumptions,
      };
    });

    res.json(result);
  } catch (e) {
    browser = null;
    console.error("[/analyze] error:", e.stack || e.message || e);
    res.status(500).json({ error: e.message || "Analyze failed" });
  }
});

/* -------------------- Santé -------------------- */
app.get("/", (_req, res) => res.send("OK"));
app.get("/ping", (_req, res) => res.json({ ok: true, time: Date.now() }));

/* -------------------- Shutdown -------------------- */
async function shutdown() { try { await browser?.close(); } catch {} process.exit(0); }
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);

app.listen(PORT, () => console.log("Nooki CO2 analyzer running on :" + PORT));
