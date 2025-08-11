import express from "express";
import { chromium, devices } from "playwright";

const app = express();
const PORT = process.env.PORT || 8080;

// CORS – autorise ton domaine (pendant les tests on laisse tout)
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", process.env.CORS_ORIGIN || "*");
  res.setHeader("Access-Control-Allow-Methods", "GET");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  next();
});

// Petit filet de sécurité anti-SSRF
function isForbiddenHost(u) {
  try {
    const url = new URL(u);
    const host = url.hostname.toLowerCase();
    if (host === "localhost" || host === "127.0.0.1") return true;
    if (host.endsWith(".local")) return true;
    return false;
  } catch { return true; }
}

async function analyzeOnce(url, uaDevice) {
  const browser = await chromium.launch({ args: ["--no-sandbox"] });
  const context = await browser.newContext(uaDevice || {});
  const page = await context.newPage();

  try {
    const resp = await page.goto(url, { timeout: 30000, waitUntil: "load" });
    if (!resp) throw new Error("No response");
    await page.waitForTimeout(1200); // assets tardifs

    const data = await page.evaluate(() => {
      const nav = performance.getEntriesByType('navigation')[0];
      const res = performance.getEntriesByType('resource') || [];
      let bytes = 0;
      if (nav && nav.transferSize) bytes += nav.transferSize;
      for (const r of res) bytes += (r.transferSize || r.encodedBodySize || 0);
      const duration_s = nav ? nav.duration / 1000 : 5;
      return {
        mb: bytes / (1024*1024),
        requests: res.length + 1,
        duration_s
      };
    });

    await browser.close();
    return data;
  } catch (e) {
    await browser.close();
    throw e;
  }
}

app.get("/analyze", async (req, res) => {
  const url = req.query.url;
  if (!url) return res.status(400).json({ error: "Missing url param" });
  if (isForbiddenHost(url)) return res.status(400).json({ error: "Forbidden host" });

  try {
    const mobileProfile = devices['Pixel 5'];
    const [mobile, desktop] = await Promise.allSettled([
      analyzeOnce(url, mobileProfile),
      analyzeOnce(url, null)
    ]);

    const ok = v => v.status === "fulfilled";
    if (!ok(mobile) && !ok(desktop)) throw new Error("Both runs failed");

    let mb, reqs, dur;
    if (ok(mobile) && ok(desktop)) {
      mb  = (mobile.value.mb + desktop.value.mb) / 2;
      reqs = Math.round((mobile.value.requests + desktop.value.requests) / 2);
      dur = (mobile.value.duration_s + desktop.value.duration_s) / 2;
    } else {
      const v = ok(mobile) ? mobile.value : desktop.value;
      mb = v.mb; reqs = v.requests; dur = v.duration_s;
    }

    const assumptions = {
      mobile_share: 0.6,
      network_wh_per_mb_mobile: 0.08,
      network_wh_per_mb_fixed: 0.04,
      client_power_w_mobile: 2,
      client_power_w_desktop: 20,
      server_wh_per_view: 0.03,
      grid_g_per_kwh: 45
    };

    const network_wh = mb * (assumptions.mobile_share * assumptions.network_wh_per_mb_mobile
                    + (1 - assumptions.mobile_share) * assumptions.network_wh_per_mb_fixed);

    const client_wh = (assumptions.mobile_share * assumptions.client_power_w_mobile
                    + (1 - assumptions.mobile_share) * assumptions.client_power_w_desktop) * (dur / 3600);

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
    res.status(500).json({ error: e.message || "Analyze failed" });
  }
});

app.get("/", (req, res) => res.send("OK"));
app.listen(PORT, () => console.log("Nooki CO2 analyzer on :" + PORT));
