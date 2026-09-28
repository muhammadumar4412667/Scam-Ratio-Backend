require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const dns = require("dns").promises;
const net = require("net");
const tls = require("tls");

const app = express();
const PORT = Number(process.env.PORT || 3000);

app.set("trust proxy", 1);
app.disable("x-powered-by");

app.use(helmet({ contentSecurityPolicy: false }));

const allowedOrigins = new Set([
  "https://scamratio.com",
  "https://www.scamratio.com",
  "https://muhammadumar4412667.github.io",
  "http://localhost:3000",
  "http://127.0.0.1:3000",
  "http://localhost:5500",
  "http://127.0.0.1:5500",
  "http://localhost:5502",
  "http://127.0.0.1:5502"
]);

app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.has(origin)) return callback(null, true);
    return callback(new Error("Origin is not allowed by ScamRatio API."));
  },
  credentials: true,
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Accept"]
}));

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

function normalizeUrl(input) {
  if (!input || typeof input !== "string") return null;
  let value = input.trim();
  if (!value) return null;

  if (!/^https?:\/\//i.test(value)) value = `https://${value}`;

  try {
    const url = new URL(value);
    if (!["http:", "https:"].includes(url.protocol)) return null;
    if (url.username || url.password) return null;
    return url;
  } catch {
    return null;
  }
}

function rootDomain(hostname) {
  const parts = hostname.toLowerCase().split(".").filter(Boolean);
  if (parts.length <= 2) return parts.join(".");
  const secondLevel = new Set([
    "co.uk","org.uk","ac.uk","gov.uk",
    "com.au","net.au","org.au",
    "co.nz","com.br","com.cn","com.pk",
    "co.jp","co.in"
  ]);
  const lastTwo = parts.slice(-2).join(".");
  return secondLevel.has(lastTwo)
    ? parts.slice(-3).join(".")
    : parts.slice(-2).join(".");
}

function isPrivateIp(ip) {
  if (!ip) return false;
  if (net.isIPv4(ip)) {
    const p = ip.split(".").map(Number);
    return (
      p[0] === 10 ||
      p[0] === 127 ||
      (p[0] === 169 && p[1] === 254) ||
      (p[0] === 192 && p[1] === 168) ||
      (p[0] === 172 && p[1] >= 16 && p[1] <= 31)
    );
  }
  if (net.isIPv6(ip)) {
    const n = ip.toLowerCase();
    return n === "::1" || n.startsWith("fc") || n.startsWith("fd") || n.startsWith("fe80:");
  }
  return false;
}

function timeoutSignal(ms) {
  return AbortSignal.timeout(ms);
}

async function lookupDns(hostname) {
  try {
    const addresses = await dns.lookup(hostname, { all: true });
    const ips = addresses.map(x => x.address);
    return {
      available: true,
      ips,
      privateIp: ips.some(isPrivateIp)
    };
  } catch (error) {
    return { available: false, ips: [], privateIp: false, error: error.message };
  }
}

async function checkTls(hostname) {
  return new Promise(resolve => {
    let settled = false;
    const finish = result => {
      if (settled) return;
      settled = true;
      resolve(result);
    };

    const socket = tls.connect({
      host: hostname,
      port: 443,
      servername: hostname,
      rejectUnauthorized: false,
      timeout: 7000
    });

    socket.once("secureConnect", () => {
      const cert = socket.getPeerCertificate();
      const authorized = socket.authorized;
      const validFrom = cert?.valid_from || null;
      const validTo = cert?.valid_to || null;
      const now = Date.now();
      const from = validFrom ? Date.parse(validFrom) : NaN;
      const to = validTo ? Date.parse(validTo) : NaN;
      const dateValid = Number.isFinite(from) && Number.isFinite(to) && now >= from && now <= to;

      finish({
        available: true,
        authorized,
        dateValid,
        valid: Boolean(authorized && dateValid),
        issuer: cert?.issuer?.O || cert?.issuer?.CN || null,
        subject: cert?.subject?.CN || null,
        validTo
      });
      socket.end();
    });

    socket.once("timeout", () => {
      socket.destroy();
      finish({ available: false, valid: false, error: "TLS timeout" });
    });

    socket.once("error", error => {
      socket.destroy();
      finish({ available: false, valid: false, error: error.message });
    });
  });
}

async function checkUrlhaus(url) {
  const key = process.env.URLHAUS_AUTH_KEY;
  const base = {
    source: "URLhaus",
    configured: Boolean(key),
    available: false,
    listed: false,
    status: null,
    threat: null,
    tags: [],
    reference: null,
    error: null
  };

  if (!key) {
    base.error = "URLhaus Auth-Key is not configured.";
    return base;
  }

  try {
    const body = new URLSearchParams({ url: url.toString() });
    const response = await fetch("https://urlhaus-api.abuse.ch/v1/url/", {
      method: "POST",
      headers: {
        "Auth-Key": key,
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json"
      },
      body,
      signal: timeoutSignal(10000)
    });

    const data = await response.json();
    base.available = true;

    if (data?.query_status === "ok") {
      base.listed = true;
      base.status = data.url_status || null;
      base.threat = data.threat || null;
      base.tags = Array.isArray(data.tags) ? data.tags : [];
      base.reference = data.urlhaus_reference || null;
    } else if (data?.query_status === "no_results") {
      base.listed = false;
    } else {
      base.error = data?.query_status || `HTTP ${response.status}`;
    }

    return base;
  } catch (error) {
    base.error = error.message;
    return base;
  }
}

async function checkPhishTank(url) {
  const appKey = process.env.PHISHTANK_APP_KEY || "";
  const base = {
    source: "PhishTank",
    configured: true,
    available: false,
    listed: false,
    verified: false,
    valid: false,
    phishId: null,
    detail: null,
    error: null
  };

  try {
    const body = new URLSearchParams({
      url: url.toString(),
      format: "json"
    });
    if (appKey) body.set("app_key", appKey);

    const headers = {
      "User-Agent": "ScamRatio/2.0 (website safety checker)",
      "Content-Type": "application/x-www-form-urlencoded",
      "Accept": "application/json"
    };

    // PhishTank documents the HTTP endpoint, but redirects/security layers can
    // return HTML before the JSON response reaches a server-side client.
    // Try HTTPS first, then the documented HTTP endpoint, and parse text before
    // JSON so an HTML error never crashes the check.
    const endpoints = [
      "https://checkurl.phishtank.com/checkurl/",
      "http://checkurl.phishtank.com/checkurl/"
    ];

    let lastError = null;

    for (const endpoint of endpoints) {
      try {
        const response = await fetch(endpoint, {
          method: "POST",
          headers,
          body,
          redirect: "manual",
          signal: timeoutSignal(10000)
        });

        const text = await response.text();
        const contentType = response.headers.get("content-type") || "";

        if (response.status >= 300 && response.status < 400) {
          const location = response.headers.get("location");
          if (location) {
            const redirectResponse = await fetch(location, {
              method: "POST",
              headers,
              body,
              redirect: "manual",
              signal: timeoutSignal(10000)
            });
            const redirectText = await redirectResponse.text();
            if (redirectResponse.ok) {
              let redirectData;
              try {
                redirectData = JSON.parse(redirectText);
              } catch {
                throw new Error(`PhishTank returned non-JSON content (HTTP ${redirectResponse.status})`);
              }
              return applyPhishTankResult(base, redirectData);
            }
            lastError = new Error(`PhishTank HTTP ${redirectResponse.status}`);
            continue;
          }
        }

        if (!response.ok) {
          lastError = new Error(`PhishTank HTTP ${response.status}`);
          continue;
        }

        let data;
        try {
          data = JSON.parse(text);
        } catch {
          lastError = new Error(
            `PhishTank returned non-JSON content (HTTP ${response.status}, ${contentType || "unknown content type"})`
          );
          continue;
        }

        return applyPhishTankResult(base, data);
      } catch (error) {
        lastError = error;
      }
    }

    throw lastError || new Error("PhishTank request failed");
  } catch (error) {
    base.error = error.message;
    return base;
  }
}

function applyPhishTankResult(base, data) {
  base.available = true;

  const result = data?.results || {};
  base.listed = String(result.in_database).toLowerCase() === "true";
  base.verified = ["y", "yes", "true", "1"].includes(String(result.verified).toLowerCase());
  base.valid = ["y", "yes", "true", "1"].includes(String(result.valid).toLowerCase());
  base.phishId = result.phish_id || null;
  base.detail = result.phish_detail_page || null;

  return base;
}

async function checkThreatFox(indicator) {
  const key = process.env.THREATFOX_AUTH_KEY || process.env.URLHAUS_AUTH_KEY;
  const base = {
    source: "ThreatFox",
    configured: Boolean(key),
    available: false,
    listed: false,
    matches: [],
    error: null
  };

  if (!key) {
    base.error = "ThreatFox/abuse.ch Auth-Key is not configured.";
    return base;
  }

  try {
    const body = {
      query: "search_ioc",
      search_term: indicator,
      exact_match: true
    };

    const response = await fetch("https://threatfox-api.abuse.ch/api/v1/", {
      method: "POST",
      headers: {
        "Auth-Key": key,
        "Content-Type": "application/json",
        "Accept": "application/json"
      },
      body: JSON.stringify(body),
      signal: timeoutSignal(10000)
    });

    const data = await response.json();
    base.available = true;

    if (data?.query_status === "ok" && Array.isArray(data.data)) {
      base.matches = data.data.slice(0, 10);
      base.listed = base.matches.length > 0;
    } else if (data?.query_status === "no_result") {
      base.listed = false;
    } else if (data?.query_status && data.query_status !== "no_result") {
      base.error = data.query_status;
    }

    return base;
  } catch (error) {
    base.error = error.message;
    return base;
  }
}

async function checkRdap(domain) {
  const base = {
    source: "RDAP",
    available: false,
    createdAt: null,
    ageDays: null,
    registrar: null,
    error: null
  };

  try {
    const urls = [];
    const tld = String(domain).split(".").pop().toLowerCase();
    if (tld === "com") {
      urls.push(`https://rdap.verisign.com/com/v1/domain/${encodeURIComponent(domain)}`);
    }
    urls.push(`https://rdap.org/domain/${encodeURIComponent(domain)}`);

    let lastStatus = null;
    let data = null;
    for (const rdapUrl of urls) {
      const response = await fetch(
        rdapUrl,
        { headers: { Accept: "application/rdap+json, application/json" }, signal: timeoutSignal(8000) }
      );
      lastStatus = response.status;
      if (response.ok) {
        data = await response.json();
        break;
      }
    }

    if (!data) {
      base.error = `RDAP HTTP ${lastStatus}`;
      return base;
    }
    base.available = true;

    const events = Array.isArray(data.events) ? data.events : [];
    const registration = events.find(e =>
      ["registration", "registered"].includes(String(e.eventAction).toLowerCase())
    );

    if (registration?.eventDate) {
      base.createdAt = registration.eventDate;
      const created = Date.parse(registration.eventDate);
      if (Number.isFinite(created)) {
        base.ageDays = Math.max(0, Math.floor((Date.now() - created) / 86400000));
      }
    }

    const entity = Array.isArray(data.entities)
      ? data.entities.find(e => Array.isArray(e.roles) && e.roles.includes("registrar"))
      : null;

    const vcard = entity?.vcardArray?.[1];
    if (Array.isArray(vcard)) {
      const fn = vcard.find(x => x?.[0] === "fn");
      base.registrar = fn?.[3] || null;
    }

    return base;
  } catch (error) {
    base.error = error.message;
    return base;
  }
}

function pushWarning(warnings, type, message, source) {
  warnings.push({ type, message, source });
}

function pushPositive(positives, type, message, source) {
  positives.push({ type, message, source });
}

function scoreLocalSignals(url, dnsInfo, tlsInfo, rdap) {
  let risk = 0;
  const warnings = [];
  const positives = [];

  const host = url.hostname.toLowerCase();
  const full = url.toString().toLowerCase();

  if (url.protocol === "https:") {
    pushPositive(positives, "transport", "Website uses HTTPS encryption.", "ScamRatio");
  } else {
    risk += 18;
    pushWarning(warnings, "transport", "Website does not use HTTPS.", "ScamRatio");
  }

  if (net.isIP(host)) {
    risk += 25;
    pushWarning(warnings, "domain", "The website uses an IP address instead of a normal domain.", "ScamRatio");
  }

  if (full.length > 180) {
    risk += 8;
    pushWarning(warnings, "url", "The URL is unusually long.", "ScamRatio");
  }

  if (host.includes("xn--")) {
    risk += 12;
    pushWarning(warnings, "domain", "The domain uses Punycode, which can be used in look-alike domains.", "ScamRatio");
  }

  const suspiciousWords = [
    "verify", "verification", "secure-login", "account-update",
    "password", "wallet", "bonus", "free-money", "gift",
    "airdrop", "prize", "claim", "login", "signin", "support"
  ];
  const found = suspiciousWords.filter(word => host.includes(word));
  if (found.length) {
    risk += Math.min(20, found.length * 5);
    pushWarning(
      warnings,
      "domain",
      `Domain contains potentially suspicious keywords: ${found.join(", ")}.`,
      "ScamRatio"
    );
  }

  if (host.split(".").length >= 5) {
    risk += 8;
    pushWarning(warnings, "domain", "The domain contains many subdomains.", "ScamRatio");
  }

  if (!dnsInfo.available) {
    risk += 18;
    pushWarning(warnings, "dns", "DNS information could not be confirmed.", "ScamRatio");
  } else {
    pushPositive(positives, "dns", "The domain resolves through DNS.", "ScamRatio");
  }

  if (dnsInfo.privateIp) {
    risk += 25;
    pushWarning(warnings, "dns", "The domain resolved to a private/local IP address.", "ScamRatio");
  }

  if (url.protocol === "https:") {
    if (tlsInfo.available && tlsInfo.valid) {
      pushPositive(positives, "ssl", "The website has a valid SSL/TLS certificate.", "ScamRatio");
    } else {
      risk += 10;
      pushWarning(warnings, "ssl", "The SSL/TLS certificate could not be fully verified.", "ScamRatio");
    }
  }

  if (rdap.available && typeof rdap.ageDays === "number") {
    if (rdap.ageDays < 30) {
      risk += 20;
      pushWarning(warnings, "domain-age", "The domain was registered less than 30 days ago.", "RDAP");
    } else if (rdap.ageDays < 180) {
      risk += 10;
      pushWarning(warnings, "domain-age", "The domain is relatively new.", "RDAP");
    } else if (rdap.ageDays >= 730) {
      pushPositive(positives, "domain-age", "The domain has been registered for at least two years.", "RDAP");
    }
  }

  return { risk, warnings, positives };
}

function uniqueMessages(items) {
  const seen = new Set();
  return items.filter(item => {
    if (!item?.message || seen.has(item.message)) return false;
    seen.add(item.message);
    return true;
  });
}

async function performScamCheck(input) {
  const url = normalizeUrl(input);
  if (!url) throw new Error("Please enter a valid website URL.");

  const hostname = url.hostname.toLowerCase();
  const domain = rootDomain(hostname);

  const [dnsInfo, tlsInfo, rdap, urlhaus, phishtank, threatfox] =
    await Promise.all([
      lookupDns(hostname),
      url.protocol === "https:" ? checkTls(hostname) : Promise.resolve({ available: false, valid: false }),
      checkRdap(domain),
      checkUrlhaus(url),
      checkPhishTank(url),
      checkThreatFox(domain)
    ]);

  const local = scoreLocalSignals(url, dnsInfo, tlsInfo, rdap);

  let risk = local.risk;
  const warnings = [...local.warnings];
  const positives = [...local.positives];

  if (urlhaus.listed) {
    risk = Math.max(risk + 55, 85);
    pushWarning(
      warnings,
      "urlhaus",
      `URLhaus has this URL listed as a known malware-related URL${urlhaus.threat ? ` (${urlhaus.threat})` : ""}.`,
      "URLhaus"
    );
  } else if (urlhaus.available) {
    pushPositive(positives, "urlhaus", "URLhaus did not find this exact URL in its malware URL database.", "URLhaus");
  }

  if (phishtank.listed && (phishtank.verified || phishtank.valid)) {
    risk = Math.max(risk + 60, 90);
    pushWarning(
      warnings,
      "phishtank",
      "PhishTank has this URL in its phishing database.",
      "PhishTank"
    );
  } else if (phishtank.available && !phishtank.listed) {
    pushPositive(positives, "phishtank", "PhishTank did not find this URL in its current lookup.", "PhishTank");
  }

  if (threatfox.listed) {
    const confidence = threatfox.matches.reduce(
      (max, item) => Math.max(max, Number(item.confidence_level || 0)),
      0
    );
    risk = Math.max(risk + (confidence >= 80 ? 40 : 25), confidence >= 80 ? 80 : 65);
    const malware = threatfox.matches[0]?.malware_printable || threatfox.matches[0]?.malware || "malicious infrastructure";
    pushWarning(
      warnings,
      "threatfox",
      `ThreatFox has an exact-match indicator for this domain (${malware}).`,
      "ThreatFox"
    );
  } else if (threatfox.available) {
    pushPositive(positives, "threatfox", "ThreatFox did not find an exact IOC match for this domain.", "ThreatFox");
  }

  const sourceHits = [urlhaus.listed, phishtank.listed && (phishtank.verified || phishtank.valid), threatfox.listed]
    .filter(Boolean).length;

  if (sourceHits >= 2) risk = Math.max(risk, 95);
  else if (sourceHits === 1) risk = Math.max(risk, 75);

  risk = Math.max(0, Math.min(100, Math.round(risk)));

  let status = "safe";
  if (risk >= 70) status = "danger";
  else if (risk >= 40) status = "warning";

  const finalWarnings = uniqueMessages(warnings);
  const finalPositives = uniqueMessages(positives);

  let summary;
  if (risk >= 70) {
    summary = "Multiple risk signals were detected. Review the warnings carefully before trusting this website.";
  } else if (risk >= 40) {
    summary = "Some risk signals were detected. Review the available website information before trusting it.";
  } else if (finalWarnings.length) {
    summary = "The website has a relatively low risk score, but some signals should still be reviewed.";
  } else {
    summary = "No major warning signals were detected by the checks currently available.";
  }

  return {
    success: true,
    score: risk,
    status,
    summary,
    target: {
      input: input,
      url: url.toString(),
      domain,
      hostname,
      protocol: url.protocol
    },
    positives: finalPositives,
    warnings: finalWarnings,
    checks: {
      urlhaus,
      phishtank,
      threatfox,
      dns: dnsInfo,
      tls: tlsInfo,
      rdap
    },
    meta: {
      engine: "ScamRatio Multi-Source Engine v2",
      checkedAt: new Date().toISOString(),
      sourcesConfigured: {
        urlhaus: Boolean(process.env.URLHAUS_AUTH_KEY),
        phishtank: true,
        threatfox: Boolean(process.env.THREATFOX_AUTH_KEY || process.env.URLHAUS_AUTH_KEY)
      }
    }
  };
}

app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    service: "ScamRatio API",
    status: "online",
    engine: "ScamRatio Multi-Source Engine v2",
    time: new Date().toISOString()
  });
});

app.get("/api/check", async (req, res) => {
  try {
    const input = req.query.url || req.query.domain;
    if (!input) return res.status(400).json({ success: false, error: "Please provide a website URL." });
    return res.json(await performScamCheck(input));
  } catch (error) {
    console.error("GET /api/check:", error);
    return res.status(500).json({ success: false, error: error.message || "Website check failed." });
  }
});

app.post("/api/check", async (req, res) => {
  try {
    const input = req.body?.url || req.body?.domain;
    if (!input) return res.status(400).json({ success: false, error: "Please provide a website URL." });
    return res.json(await performScamCheck(input));
  } catch (error) {
    console.error("POST /api/check:", error);
    return res.status(500).json({ success: false, error: error.message || "Website check failed." });
  }
});

app.get("/", (req, res) => {
  res.json({
    success: true,
    name: "ScamRatio API",
    message: "ScamRatio backend is running.",
    endpoints: ["/api/health", "/api/check?url=https://example.com"]
  });
});

app.use((error, req, res, next) => {
  console.error("ScamRatio server error:", error);
  if (error?.message === "Origin is not allowed by ScamRatio API.") {
    return res.status(403).json({ success: false, error: error.message });
  }
  return res.status(500).json({ success: false, error: "Internal server error." });
});

app.listen(PORT, () => {
  console.log(`ScamRatio API listening on port ${PORT}`);
});
