import express from "express";
import bodyParser from "body-parser";
import path from "node:path";
import { fileURLToPath } from "node:url";
import dotenv from "dotenv";
import Stripe from "stripe";
import { Resend } from "resend";
import { v4 as uuidv4 } from "uuid";
import fetch from "node-fetch";

dotenv.config();

const app = express();
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
const resend = new Resend(process.env.RESEND_API_KEY);

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/**
 * 1) Webhook Stripe (PRIMA dei body parser; usa raw body)
 */
app.post("/webhook", express.raw({ type: "application/json" }), async (req, res) => {
  const sig = req.headers["stripe-signature"];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type === "checkout.session.completed") {
    const session = event.data.object;

    // Idempotenza: processa la sessione una sola volta
    const handled = await redisCommand("SET", `stripe:handled:${session.id}`, "1", "NX", "EX", "2592000");
    if (handled.result !== "OK") {
      return res.json({ received: true, duplicated: true });
    }

    const email = session.metadata?.email;
    const attempts = Number(session.metadata?.attempts || 0);
    const token = uuidv4();

    // Salva token e tentativi con TTL
    const ttl = process.env.TOKEN_TTL_SECONDS ? String(process.env.TOKEN_TTL_SECONDS) : "2592000";
    await redisCommand("SET", `token:${token}:meta`, JSON.stringify({ email, createdAt: Date.now() }), "EX", ttl);
    await redisCommand("SET", `token:${token}:attempts`, String(attempts), "EX", ttl);

    // Tracciamento codice sconto applicato (se presente)
    try {
      const sess = await stripe.checkout.sessions.retrieve(session.id, {
        expand: ["total_details.breakdown.discounts"]
      });
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
          amount: d.amount,        // centesimi scontati totali
          currency: sess.currency,
          couponId: promo.coupon?.id,
          percentOff: promo.coupon?.percent_off ?? null,
          amountOff: promo.coupon?.amount_off ?? null
        });
      }
    } catch (e) {
      console.error("Promo tracking error:", e?.message || e);
    }

    // Invia email con link al calcolatore
    const link = `${process.env.PUBLIC_BASE_URL}/public/calculator.html?t=${token}`;
    const from = process.env.RESEND_FROM || "onboarding@resend.dev";
    const replyTo = process.env.REPLY_TO || undefined;
    try {
      await resend.emails.send({
        from: `DC Calculator <${from}>`,
        to: email,
        replyTo,
        subject: "Il tuo link al calcolatore",
        html: `<p>Ciao! Ecco il tuo link personale al calcolatore:</p>
               <p><a href="${link}">${link}</a></p>
               <p>Tentativi disponibili: <strong>${attempts}</strong></p>`
      });
    } catch (e) {
      console.error("Errore invio email Resend:", e?.message || e);
    }
  }

  res.json({ received: true });
});

/**
 * 2) Body parser per le altre route
 */
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

/**
 * 3) Statici
 */
app.use("/public", express.static(path.join(__dirname, "public"), { index: false }));
app.get("/", (_, res) => res.redirect("/public/index.html"));

/**
 * 4) Upstash Redis (REST)
 */
const UPSTASH_URL = process.env.UPSTASH_REDIS_REST_URL;
const UPSTASH_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;
const TOKEN_TTL_SECONDS = Number(process.env.TOKEN_TTL_SECONDS || 60 * 60 * 24 * 30);

async function redisCommand(...args) {
  const r = await fetch(UPSTASH_URL, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${UPSTASH_TOKEN}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ command: args })
  });
  const j = await r.json();
  if (!r.ok) throw new Error(`Upstash error ${r.status}: ${JSON.stringify(j)}`);
  return j; // { result: ... }
}

// Helpers tentativi
async function getAttemptsKey(token) { return `token:${token}:attempts`; }
async function getMetaKey(token) { return `token:${token}:meta`; }

async function getAttempts(token) {
  const meta = await redisCommand("GET", await getMetaKey(token));
  if (!meta.result) return null;
  const att = await redisCommand("GET", await getAttemptsKey(token));
  return Math.max(0, Number(att.result || 0));
}
async function consumeAttempt(token) {
  const meta = await redisCommand("GET", await getMetaKey(token));
  if (!meta.result) return { error: "Token non valido" };
  const decr = await redisCommand("DECR", await getAttemptsKey(token));
  let remaining = Number(decr.result);
  if (remaining < 0) {
    await redisCommand("SET", await getAttemptsKey(token), "0", "EX", String(TOKEN_TTL_SECONDS));
    return { error: "Tentativi esauriti" };
  }
  if (TOKEN_TTL_SECONDS > 0) {
    await redisCommand("EXPIRE", await getAttemptsKey(token), String(TOKEN_TTL_SECONDS));
    await redisCommand("EXPIRE", await getMetaKey(token), String(TOKEN_TTL_SECONDS));
  }
  return { remaining };
}

/**
 * 5) Prezzi Stripe (EUR) – Sostituisci con i tuoi Price ID "price_..."
 */
const PRICES = {
  "1": "prod_TD392UBI1d9WYT",   // €30
  "3": "prod_TD3NUk7SGePMeF",   // €50
  "10": "prod_TD3OlSLSplG7IE"  // €100
};

/**
 * 6) Publishable Key per il client
 */
app.get("/api/public-config", (req, res) => {
  res.json({ stripePk: process.env.STRIPE_PUBLISHABLE_KEY || "" });
});

/**
 * 7) Utility sconto: risolve un promotion code (es. ESTATE10) in ID Stripe
 */
async function findPromotionCodeId(code) {
  if (!code) return null;
  const cleaned = String(code).trim();
  if (!cleaned) return null;
  const list = await stripe.promotionCodes.list({ code: cleaned, active: true, limit: 1 });
  const pc = list.data?.[0];
  return pc?.id || null;
}

/**
 * 8) Tracciamento sconto su Upstash
 */
async function trackPromoUsage(code, data) {
  if (!code) return;
  await redisCommand("INCR", `promo:${code}:count`);
  await redisCommand("LPUSH", `promo:${code}:uses`, JSON.stringify({ code, ...data, ts: Date.now() }));
  await redisCommand("LTRIM", `promo:${code}:uses`, "0", "99");
}

/**
 * 9) Checkout Session (supporta promoCode facoltativo)
 * Body: { email, pkg, promoCode? }
 */
app.post("/api/create-checkout-session", async (req, res) => {
  const { email, pkg, promoCode } = req.body || {};
  if (!email || !PRICES[pkg]) {
    return res.status(400).json({ error: "Parametri non validi" });
  }
  const isEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  if (!isEmail) return res.status(400).json({ error: "Email non valida" });

  try {
    const discounts = [];
    if (promoCode && String(promoCode).trim()) {
      const promoId = await findPromotionCodeId(promoCode);
      if (!promoId) {
        return res.status(400).json({ error: "Codice sconto non valido o non attivo" });
      }
      discounts.push({ promotion_code: promoId });
    }

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ["card"],
      customer_email: email,
      line_items: [{ price: PRICES[pkg], quantity: 1 }],
      mode: "payment",
      allow_promotion_codes: true, // consenti inserimento anche su pagina Stripe
      discounts: discounts.length ? discounts : undefined,
      success_url: `${process.env.PUBLIC_BASE_URL}/public/success.html`,
      cancel_url: `${process.env.PUBLIC_BASE_URL}/public/cancel.html`,
      metadata: { email, attempts: String(pkg) }
    });
    res.json({ id: session.id });
  } catch (err) {
    console.error("Stripe create session error:", err);
    res.status(500).json({ error: "Errore nella creazione della sessione di pagamento" });
  }
});

/**
 * 10) API tentativi (status/consume)
 */
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

/**
 * 11) Admin opzionale: statistiche utilizzo promo
 * GET /api/promo-usage?code=ESTATE10
 * Header: x-admin-key: <ADMIN_API_KEY>
 */
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
  try { list = (uses.result || []).map(x => JSON.parse(x)); } catch {}
  res.json({ code, count: Number(count.result || 0), recent: list });
});

/**
 * 12) Avvio
 */
const port = process.env.PORT || 4242;
app.listen(port, () => {
  console.log(`Server attivo su ${process.env.PUBLIC_BASE_URL || `http://localhost:${port}`}`);
});
