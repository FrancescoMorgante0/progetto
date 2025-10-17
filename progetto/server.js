import express from "express";
import path from "node:path";
import { fileURLToPath } from "node:url";
import dotenv from "dotenv";
import Stripe from "stripe";
import { Resend } from "resend";
import { v4 as uuidv4 } from "uuid";

dotenv.config();

/* ------------------------ 0) APP E SDK ------------------------ */
const app = express();
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
const resend = new Resend(process.env.RESEND_API_KEY);

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/* ------------------------ 1) VALIDAZIONE ENV ------------------------ */
[
  "STRIPE_SECRET_KEY",
  "STRIPE_PUBLISHABLE_KEY",
  "PUBLIC_BASE_URL",
  "UPSTASH_REDIS_REST_URL",
  "UPSTASH_REDIS_REST_TOKEN",
  "RESEND_API_KEY",
].forEach((k) => {
  if (!process.env[k]) console.warn("[env] Manca", k);
});

/* ------------------------ 2) fetch compatibile (Node 16/18/20) ------------------------ */
async function compatFetch(...args) {
  let f = globalThis.fetch;
  if (!f) {
    const mod = await import("node-fetch");
    f = mod.default;
  }
  return f(...args);
}

/* ------------------------ 3) UPSTASH (REST) - compat a più formati ------------------------ */
const UPSTASH_URL_RAW = (process.env.UPSTASH_REDIS_REST_URL || "").replace(/\/+$/, "");
const UPSTASH_URL = UPSTASH_URL_RAW; // senza trailing slash
const UPSTASH_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;
const TOKEN_TTL_SECONDS = Number(process.env.TOKEN_TTL_SECONDS || 60 * 60 * 24 * 30);

// Prova i 3 formati: POST [array] -> POST {command,args} -> GET /CMD/args...
async function redisCommand(...args) {
  if (!UPSTASH_URL || !UPSTASH_TOKEN) throw new Error("Upstash URL/TOKEN mancanti");
  if (!args.length) throw new Error("redisCommand: nessun argomento");

  const cmd = String(args[0] ?? "");
  const rest = args.slice(1).map((a) => (a === undefined || a === null ? "" : String(a)));

  const headers = {
    Authorization: `Bearer ${UPSTASH_TOKEN}`,
    "Content-Type": "application/json",
  };

  // 1) POST con body array root: ["SET","k","v","EX","60"]
  try {
    const resp1 = await compatFetch(UPSTASH_URL, {
      method: "POST",
      headers,
      body: JSON.stringify([cmd, ...rest]),
    });
    const text1 = await resp1.text();
    let json1;
    try { json1 = JSON.parse(text1); } catch { json1 = { raw: text1 }; }
    if (resp1.ok && !json1?.error) return json1;
    throw new Error(`POST-array failed: ${resp1.status} ${text1}`);
  } catch (e1) {
    // 2) POST con body object: {command:"SET", args:["k","v","EX","60"]}
    try {
      const resp2 = await compatFetch(UPSTASH_URL, {
        method: "POST",
        headers,
        body: JSON.stringify({ command: cmd, args: rest }),
      });
      const text2 = await resp2.text();
      let json2;
      try { json2 = JSON.parse(text2); } catch { json2 = { raw: text2 }; }
      if (resp2.ok && !json2?.error) return json2;
      throw new Error(`POST-object failed: ${resp2.status} ${text2}`);
    } catch (e2) {
      // 3) GET stile path: /SET/k/v/EX/60
      try {
        const path = [cmd, ...rest].map(encodeURIComponent).join("/");
        const resp3 = await compatFetch(`${UPSTASH_URL}/${path}`, {
          method: "GET",
          headers: { Authorization: `Bearer ${UPSTASH_TOKEN}` },
        });
        const text3 = await resp3.text();
        let json3;
        try { json3 = JSON.parse(text3); } catch { json3 = { raw: text3 }; }
        if (resp3.ok && !json3?.error) return json3;
        throw new Error(`GET-path failed: ${resp3.status} ${text3}`);
      } catch (e3) {
        throw new Error(`Upstash all formats failed: ${e1?.message} | ${e2?.message} | ${e3?.message}`);
      }
    }
  }
}

const getAttemptsKey = (token) => `token:${token}:attempts`;
const getMetaKey = (token) => `token:${token}:meta`;

async function getAttempts(token) {
  const meta = await redisCommand("GET", getMetaKey(token));
  if (!meta.result) return null;
  const att = await redisCommand("GET", getAttemptsKey(token));
  return Math.max(0, Number(att.result || 0));
}

async function consumeAttempt(token) {
  const meta = await redisCommand("GET", getMetaKey(token));
  if (!meta.result) return { error: "Token non valido" };
  const decr = await redisCommand("DECR", getAttemptsKey(token));
  let remaining = Number(decr.result);
  if (remaining < 0) {
    if (TOKEN_TTL_SECONDS > 0) {
      await redisCommand("SET", getAttemptsKey(token), "0", "EX", String(TOKEN_TTL_SECONDS));
    } else {
      await redisCommand("SET", getAttemptsKey(token), "0");
    }
    return { error: "Tentativi esauriti" };
  }
  if (TOKEN_TTL_SECONDS > 0) {
    await redisCommand("EXPIRE", getAttemptsKey(token), String(TOKEN_TTL_SECONDS));
    await redisCommand("EXPIRE", getMetaKey(token), String(TOKEN_TTL_SECONDS));
  }
  // Se TTL è zero, non aggiornare la scadenza (rimane persistente)
  return { remaining };
}

async function trackPromoUsage(code, data) {
  if (!code) return;
  await redisCommand("INCR", `promo:${code}:count`);
  await redisCommand("LPUSH", `promo:${code}:uses`, JSON.stringify({ code, ...data, ts: Date.now() }));
  await redisCommand("LTRIM", `promo:${code}:uses`, "0", "99");
}

/* ------------------------ 4) Helper firma: 1 o 2 segreti ------------------------ */
function constructEventWithSecrets(req, sig) {
  const secrets = [
    process.env.STRIPE_WEBHOOK_SECRET,        // unico endpoint consigliato
    process.env.STRIPE_WEBHOOK_SECRET_ALT,    // opzionale finché non disattivi i duplicati
  ].filter(Boolean);

  let lastErr = null;
  for (const s of secrets) {
    try {
      const evt = stripe.webhooks.constructEvent(req.body, sig, s);
      if (s === process.env.STRIPE_WEBHOOK_SECRET_ALT) {
        console.log("[webhook] matched ALT secret");
      }
      return evt;
    } catch (e) {
      lastErr = e;
    }
  }
  throw lastErr || new Error("Nessun segreto configurato");
}

/* ------------------------ 5) WEBHOOK (PRIMA dei parser JSON) ------------------------ */
app.post("/webhook", express.raw({ type: "application/json" }), async (req, res) => {
  const sig = req.headers["stripe-signature"];
  let event;

  try {
    event = constructEventWithSecrets(req, sig);
  } catch (err) {
    console.error("Webhook signature error:", err?.message || err);
    console.error("Diag:", {
      hasSigHeader: Boolean(sig),
      bodyType: Buffer.isBuffer(req.body) ? "buffer" : typeof req.body,
      bodyLen: Buffer.isBuffer(req.body) ? req.body.length : undefined,
    });
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  // ACK immediato per eliminare 502/timeout
  if (event.type === "checkout.session.completed") {
    res.status(200).send("OK");

    setImmediate(async () => {
      let session = event.data.object;

      // Se payload è "thin", fai retrieve per ottenere email/metadata
      if (!session?.metadata?.email && !session?.customer_details?.email && !session?.customer_email) {
        try {
          session = await stripe.checkout.sessions.retrieve(session.id, {
            expand: ["customer_details", "total_details.breakdown.discounts"],
          });
        } catch (e) {
          console.error("Retrieve session for thin payload failed:", e?.message || e);
        }
      }

      try {
        // idempotenza
        const already = await redisCommand("GET", `stripe:handled:${session.id}`);
        if (already?.result) return;

        // lock
        const lockKey = `stripe:processing:${session.id}`;
        const lock = await redisCommand("SET", lockKey, "1", "NX", "EX", "300");
        if (lock.result !== "OK") return;

        const email =
          session?.metadata?.email ||
          session?.customer_details?.email ||
          session?.customer_email ||
          null;
        const attempts = Number(session?.metadata?.attempts || 0);

        if (!email) {
          console.error("Webhook (bg): email mancante", { sessionId: session.id });
          await redisCommand("DEL", lockKey);
          return;
        }

        // token + TTL
        const token = uuidv4();
        const ttl = Number(process.env.TOKEN_TTL_SECONDS || 60 * 60 * 24 * 30);
        if (ttl > 0) {
          await redisCommand("SET", `token:${token}:meta`, JSON.stringify({ email, createdAt: Date.now() }), "EX", String(ttl));
          await redisCommand("SET", `token:${token}:attempts`, String(attempts), "EX", String(ttl));
        } else {
          await redisCommand("SET", `token:${token}:meta`, JSON.stringify({ email, createdAt: Date.now() }));
          await redisCommand("SET", `token:${token}:attempts`, String(attempts));
        }

        // tracking sconti (best-effort)
        try {
          const sess = await stripe.checkout.sessions.retrieve(session.id, { expand: ["total_details.breakdown.discounts"] });
          const breakdown = sess.total_details?.breakdown?.discounts || [];
          for (const d of breakdown) {
            const promoId = d.discount?.promotion_code;
            if (!promoId) continue;
            const promo = await stripe.promotionCodes.retrieve(promoId, { expand: ["coupon"] });
            const code = promo.code;
            await trackPromoUsage(code, {
              email,
              sessionId: session.id,
              token,
              amount: d.amount,
              currency: sess.currency,
              couponId: promo.coupon?.id,
              percentOff: promo.coupon?.percent_off ?? null,
              amountOff: promo.coupon?.amount_off ?? null,
            });
          }
        } catch (e) {
          console.error("Promo tracking error:", e?.message || e);
        }

        // invio email
        const from = process.env.RESEND_FROM || "onboarding@resend.dev";
        const replyTo = process.env.REPLY_TO || undefined;
        const link = `${process.env.PUBLIC_BASE_URL}/public/calculator.html?t=${token}`;

        try {
          await resend.emails.send({
            from: `Ecosystem solver <${from}>`,
            to: email,
            ...(replyTo ? { replyTo } : {}),
            subject: "Link to Solver",
            html: `<p>Hi! this is your personal link to the solver:</p>
                   <p><a href="${link}">${link}</a></p>
                   <p>Tavailable attempts: <strong>${attempts}</strong>
                      The developers of this solver have no affiliation with McKinsey & Company. Use this solver in accordance with McKinsey’s policies.</p>`,
          });
        } catch (sendErr) {
          console.error("Errore invio email Resend:", sendErr?.message || sendErr);
          await redisCommand("DEL", lockKey);
          return;
        }

        await redisCommand("SET", `stripe:handled:${session.id}`, "1", "EX", "2592000");
        await redisCommand("DEL", lockKey);
        console.log("[webhook] completed + email sent", { sessionId: session.id, email });
      } catch (e) {
        console.error("Webhook (bg) processing error:", e?.message || e);
      }
    });

    return; // abbiamo già risposto 200
  }

  // altri eventi: ack veloce
  return res.json({ received: true });
});

/* ------------------------ 6) PARSER E LOGGING ------------------------ */
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use((req, res, next) => {
  if (req.path.startsWith("/api/")) {
    console.log("[api]", req.method, req.path, "body=", req.body);
  }
  next();
});

/* ------------------------ 7) ENDPOINT TEST UPSTASH ------------------------ */
app.get("/api/kv-ping", async (req, res) => {
  try {
    const pong = await redisCommand("PING");
    res.json({ ok: true, pong });
  } catch (e) {
    console.error("[kv-ping] error:", e?.message || e);
    res.status(500).json({ ok: false, error: e?.message || String(e) });
  }
});

app.get("/api/kv-test", async (req, res) => {
  try {
    const k = "kv:test:ping";
    const v = `ok-${Date.now()}`;
    await redisCommand("SET", k, v, "EX", "60");
    const got = await redisCommand("GET", k);
    res.json({ ok: true, set: v, get: got?.result ?? null });
  } catch (e) {
    console.error("[kv-test] error:", e?.message || e);
    res.status(500).json({ ok: false, error: e?.message || String(e) });
  }
});

/* ------------------------ 8) STATICI ------------------------ */
app.use("/public", express.static(path.join(__dirname, "public"), { index: false }));
app.get("/", (_, res) => res.redirect("/public/index.html"));

/* ------------------------ 9) PRICE IDs (TEST) ------------------------ */
const PRICES = {
  "1": "price_1SIxxEJvC2sKkuzIWrlbX3L6",
  "3": "price_1SIxyMJvC2sKkuzIekxASJtF",
  "10": "price_1SIxz9JvC2sKkuzIwstgUdQN",
};

/* ------------------------ 10) CONFIG PUBBLICA (PK) ------------------------ */
app.get("/api/public-config", (req, res) => {
  res.json({ stripePk: process.env.STRIPE_PUBLISHABLE_KEY || "" });
});

/* ------------------------ 11) PROMO LOOKUP ------------------------ */
async function findPromotionCodeId(code) {
  if (!code) return null;
  const cleaned = String(code).trim();
  if (!cleaned) return null;
  const list = await stripe.promotionCodes.list({ code: cleaned, active: true, limit: 1 });
  return list.data?.[0]?.id || null;
}

/* ------------------------ 12) CREATE CHECKOUT SESSION ------------------------ */
app.post("/api/create-checkout-session", async (req, res) => {
  const { email, pkg, promoCode } = req.body || {};
  if (!email || !PRICES[pkg]) return res.status(400).json({ error: "Parametri non validi" });
  const isEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  if (!isEmail) return res.status(400).json({ error: "Email non valida" });

  const priceId = PRICES[pkg];
  if (!priceId.startsWith("price_")) {
    return res.status(500).json({ error: "ID nel mapping PRICES NON è un Price ID (sostituisci prod_... con price_...)" });
  }

  try {
    const discounts = [];
    if (promoCode && String(promoCode).trim()) {
      const promoId = await findPromotionCodeId(promoCode);
      if (!promoId) return res.status(400).json({ error: "Codice sconto non valido o non attivo" });
      discounts.push({ promotion_code: promoId });
    }

    const session = await stripe.checkout.sessions.create({
      mode: "payment",
      payment_method_types: ["card"],
      customer_email: email,
      line_items: [{ price: priceId, quantity: 1 }],
      allow_promotion_codes: true,
      discounts: discounts.length ? discounts : undefined,
      success_url: `${process.env.PUBLIC_BASE_URL}/public/success.html?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.PUBLIC_BASE_URL}/public/cancel.html`,
      metadata: { email, attempts: String(pkg) },
    });

    console.log("[stripe] session created", session.id);
    res.json({ id: session.id });
  } catch (err) {
    const payload = {
      message: err?.message,
      type: err?.type,
      code: err?.code,
      param: err?.param,
      requestId: err?.raw?.requestId,
      statusCode: err?.statusCode || 500,
    };
    console.error("[stripe] create session FAILED", payload);
    res.status(payload.statusCode).json({ ok: false, error: payload });
  }
});

/* ------------------------ 13) API TENTATIVI ------------------------ */
app.post("/api/attempts", async (req, res) => {
  const { action, token } = req.body || {};
  if (!token) return res.status(400).json({ error: "Token mancante" });
  if (action === "status") {
    const value = await getAttempts(token);
    if (value === null) return res.status(400).json({ error: "Token non valido" });
    return res.json({ remaining: value });
  }
  if (action === "consume") {
    const result = await consumeAttempt(token);
    if (result.error) return res.status(403).json({ error: result.error });
    return res.json({ remaining: result.remaining });
  }
  return res.status(400).json({ error: "Azione non valida" });
});

/* ------------------------ 14) ADMIN PROMO USAGE ------------------------ */
app.get("/api/promo-usage", async (req, res) => {
  const adminKey = req.headers["x-admin-key"];
  if (!process.env.ADMIN_API_KEY || adminKey !== process.env.ADMIN_API_KEY) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  const code = String(req.query.code || "").trim();
  if (!code) return res.status(400).json({ error: "Parametro code mancante" });
  const count = await redisCommand("GET", `promo:${code}:count`);
  const uses = await redisCommand("LRANGE", `promo:${code}:uses`, "0", "30");
  let list = [];
  try { list = (uses.result || []).map((x) => JSON.parse(x)); } catch {}
  res.json({ code, count: Number(count.result || 0), recent: list });
});

/* ------------------------ 15) TEST EMAIL ------------------------ */
app.post("/api/test-email", async (req, res) => {
  try {
    const to = req.body?.to || process.env.TEST_EMAIL_TO;
    if (!to) return res.status(400).json({ ok: false, error: "Parametro 'to' mancante (o setta TEST_EMAIL_TO in ENV)" });
    const from = process.env.RESEND_FROM || "onboarding@resend.dev";
    const replyTo = process.env.REPLY_TO || undefined;

    const r = await resend.emails.send({
      from: `DC Calculator <${from}>`,
      to,
      ...(replyTo ? { replyTo } : {}),
      subject: "Test Resend dall'app",
      html: "<p>Se vedi questa email, Resend funziona ✅</p>",
    });
    res.json({ ok: true, id: r?.id || null });
  } catch (e) {
    console.error("Test email error:", e?.message || e);
    res.status(500).json({ ok: false, error: e?.message || String(e) });
  }
});

/* ------------------------ 16) HEALTHCHECK ------------------------ */
app.get("/health", (req, res) => res.status(200).json({ ok: true }));

/* ------------------------ 17) AVVIO ------------------------ */
const port = process.env.PORT || 4242;
app.listen(port, () => {
  console.log(`[boot] listening on ${port} (Node ${process.version})`);
  console.log(`Server attivo su ${process.env.PUBLIC_BASE_URL || `http://localhost:${port}`}`);
});
