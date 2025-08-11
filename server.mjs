import express from "express";
import { chromium, devices } from "playwright";

const app = express();
const PORT = process.env.PORT || 8080;

// CORS (autorise ton domaine en prod via CORS_ORIGIN)
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", process.env.CORS_ORIGIN || "*");
  res.setHeader("Access-Control-Allow-Methods", "GET");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  next();
});

// Sécurité simple anti-SSRF
function isForbiddenHost(u) {
  try {
    const url = new URL(u);
    const host = url.hostname.toLowerCase();
    if (host === "localhost" || host === "127.0.0.1") return true;
    if (host.endsWith(".local")) return true;
    return false;
  } catch {
    return true;
  }
}

// --- ANALYSE D'UNE PASSE (mobile ou desktop) ---
async function analyzeOnce(url, uaDevice) {
  const browser = await chromium.launch({
    headless: true,
    args: ["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"]
  });

  const context = await browser.newContext({
    ...uaDevice,
    ignoreHTTPSErrors: true,
    userAgent:
      (uaDevice && uaDevice.userAgent) ||
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    viewport: (uaDevice && uaDevice.viewport) || { width: 1366, height: 768 }
  });

  const page = await context.newPage();

  // petite fonction pour lire les perfs
  const readPerf = () =>
    page.evaluate(() => {
      const nav = performance.getEntriesByType("navigation")[0];
      const res = performance.getEntriesByType("resource") || [];
      let bytes = 0;
      if (nav && nav.transferSize) bytes += nav.transferSize;
      for (const r of res) bytes += (r.transferSize || r.encodedBodySize || 0);
      // Fallback durée : min 5s pour éviter client_wh = 0
      const raw = nav ? nav.duration / 1000 : 0;
      const duration_s = Math.max(raw, 5);
      return {
        mb: bytes / (1024 * 1024),
        requests: (res?.length || 0) + 1,
        duration_s
      };
    });

  try {
    // 1) Aller jusqu'au premier octet (évite les timeouts stricts)
    const resp = await page.goto(url, { timeout: 90000, waitUntil: "commit" });
    if (!resp) throw new Error("No response from server");

    // 2) Attente souple d'un rendu minimal (sans planter si ça tarde)
    await page.waitForLoadState("domcontentloaded", { timeout: 20000 }).catch(() => {});
    await page.waitForTimeout(1200); // laisser finir quelques assets

    // 3) Lire les perfs, avec retry si "execution context destroyed" (renavigation)
    const tryRead = async () => {
      try {
        return await readPerf();
      } catch (e) {
        const msg = (e && e.message) || "";
        if (/Execution context was destroyed/i.test(msg)) {
          // la page a renavigué → on attend un peu et on réessaie
          await page.waitForLoadState("domcontentloaded", { timeout: 8000 }).catch(() => {});
          await page.waitForTimeout(800);
          return await readPerf();
        }
        throw e;
      }
    };

    const data = await tryRead();
    await browser.close();
    return data;
  } catch (e) {
    console.error("[analyzeOnce] error:", e.message);
    await browser.close();
    throw e;
  }
}

// --- RETRIES ---
async function analyzeWithRetries(url, uaDevice, attempts = 2) {
  let lastErr;
  for (let i = 0; i < attempts; i++) {
    try {
      return await analyzeOnce(url, uaDevice);
    } catch (e) {
      lastErr = e;
      await new Promise(r => setTimeout(r, 800));
    }
  }
  throw lastErr || new Error("Unknown error");
}

// --- ENDPOINT ---
app.get("/analyze", async (req, res) => {
  const url = req.query.url;
  if (!url) return res.status(400).json({ error: "Missing url param" });
  if (isForbiddenHost(url)) return res.status(400).json({ error: "Forbidden host" });

  try {
    const mobileProfile = devices["Pixel 5"];
    const [mobile, desktop] = await Promise.allSettled([
      analyzeWithRetries(url, mobileProfile, 2),
      analyzeWithRetries(url, null, 2)
    ]);

    const ok = v => v.status === "fulfilled";
    if (!ok(mobile) && !ok(desktop)) {
      const msg = `[analyze] both runs failed: mobile=${mobile?.reason?.message} desktop=${desktop?.reason?.message}`;
      console.error(msg);
      return res.status(500).json({ error: "Both runs failed" });
    }

    // Moyenne si les deux réussissent, sinon garde la passe qui marche
    let mb, reqs, dur;
    if (ok(mobile) && ok(desktop)) {
      mb = (mobile.value.mb + desktop.value.mb) / 2;
      reqs = Math.round((mobile.value.requests + desktop.value.requests) / 2);
      dur = (mobile.value.duration_s + desktop.value.duration_s) / 2;
    } else {
      const v = ok(mobile) ? mobile.value : desktop.value;
      mb = v.mb;
      reqs = v.requests;
      dur = v.duration_s;
    }

    // Hypothèses (éditables)
    const assumptions = {
      mobile_share: 0.6,
      network_wh_per_mb_mobile: 0.08,
      network_wh_per_mb_fixed: 0.04,
      client_power_w_mobile: 2,
      client_power_w_desktop: 20,
      server_wh_per_view: 0.03,
      grid_g_per_kwh: 45
    };

    // Calculs énergie + CO2
    const network_wh =
      mb *
      (assumptions.mobile_share * assumptions.network_wh_per_mb_mobile +
        (1 - assumptions.mobile_share) * assumptions.network_wh_per_mb_fixed);

    const client_wh =
      (assumptions.mobile_share * assumptions.client_power_w_mobile +
        (1 - assumptions.mobile_share) * assumptions.client_power_w_desktop) *
      (dur / 3600);

    const server_wh = assumptions.server_wh_per_view;

    const total_kwh = (network_wh + client_wh + server_wh) / 1000;
    const co2_g = total_kwh * assumptions.grid_g_per_kwh;

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
    console.error("[/analyze] fatal:", e.message);
    res.status(500).json({ error: e.message || "Analyze failed" });
  }
});

// routes simples pour tests / keep-alive
app.get("/", (req, res) => res.send("OK"));
app.get("/ping", (req, res) => res.json({ ok: true, time: Date.now() }));

app.listen(PORT, () => console.log("Nooki CO2 analyzer on :" + PORT));
