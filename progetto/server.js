import express from "express";
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

/* ------------------------ 1. VALIDAZIONE ENV MINIMA ------------------------ */
// Spostato qui per avvisare subito se mancano le chiavi
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

/* ------------------------ 2. UPSTASH REDIS (REST) - Funzioni definite qui per l'utilizzo nel Webhook ------------------------ */
const UPSTASH_URL = process.env.UPSTASH_REDIS_REST_URL;
const UPSTASH_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;
const TOKEN_TTL_SECONDS = Number(
  process.env.TOKEN_TTL_SECONDS || 60 * 60 * 24 * 30
);

async function redisCommand(...args) {
  const r = await fetch(UPSTASH_URL, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${UPSTASH_TOKEN}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ command: args }),
  });
  const j = await r.json();
  if (!r.ok)
    throw new Error(`Upstash error ${r.status}: ${JSON.stringify(j)}`);
  return j; // { result: ... }
}

// Helpers
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
    await redisCommand("SET", getAttemptsKey(token), "0", "EX", String(TOKEN_TTL_SECONDS));
    return { error: "Tentativi esauriti" };
  }
  if (TOKEN_TTL_SECONDS > 0) {
    await redisCommand("EXPIRE", getAttemptsKey(token), String(TOKEN_TTL_SECONDS));
    await redisCommand("EXPIRE", getMetaKey(token), String(TOKEN_TTL_SECONDS));
  }
  return { remaining };
}

// Funzione mancante implementata
async function trackPromoUsage(code, data) {
  if (!code) return;
  await redisCommand("INCR", `promo:${code}:count`);
  await redisCommand(
    "LPUSH",
    `promo:${code}:uses`,
    JSON.stringify({ code, ...data, ts: Date.now() })
  );
  await redisCommand("LTRIM", `promo:${code}:uses`, "0", "99");
}


/* ------------------------ 3. WEBHOOK (prima dei parser JSON) ------------------------ */
app.post(
  "/webhook",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    const sig = req.headers["stripe-signature"];
    let event;
    try {
      event = stripe.webhooks.constructEvent(
        req.body,
        sig,
        process.env.STRIPE_WEBHOOK_SECRET
      );
    } catch (err) {
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    if (event.type === "checkout.session.completed") {
      const session = event.data.object;

      // Idempotenza
      const handled = await redisCommand(
        "SET",
        `stripe:handled:${session.id}`,
        "1",
        "NX",
        "EX",
        "2592000"
      );
      if (handled.result !== "OK") {
        return res.json({ received: true, duplicated: true });
      }

      const email = session.metadata?.email;
      const attempts = Number(session.metadata?.attempts || 0);
      const token = uuidv4();

      // Salva token e tentativi
      const ttl =
        process.env.TOKEN_TTL_SECONDS || String(60 * 60 * 24 * 30); // default 30gg
      await redisCommand(
        "SET",
        `token:${token}:meta`,
        JSON.stringify({ email, createdAt: Date.now() }),
        "EX",
        String(ttl)
      );
      await redisCommand(
        "SET",
        `token:${token}:attempts`,
        String(attempts),
        "EX",
        String(ttl)
      );

      // Tracciamento sconti (best effort)
      try {
        const sess = await stripe.checkout.sessions.retrieve(session.id, {
          expand: ["total_details.breakdown.discounts"],
        });
        const breakdown = sess.total_details?.breakdown?.discounts || [];
        for (const d of breakdown) {
          const promoId = d.discount?.promotion_code;
          if (!promoId) continue;
          const promo = await stripe.promotionCodes.retrieve(promoId, {
            expand: ["coupon"],
          });
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

      // Email con link
      const link = `${process.env.PUBLIC_BASE_URL}/public/calculator.html?t=${token}`;
      // NOTA: il from deve essere un indirizzo verificato su Resend (es. info@mail.tuodominio.com)
      const from = process.env.RESEND_FROM || "mail.psgecosystem.com"; 
      const replyTo = process.env.REPLY_TO; // Correggiamo la gestione di replyTo (se undefined, non viene aggiunto)

      try {
        await resend.emails.send({
          from: `DC Calculator <${from}>`,
          to: email,
          // Correzione: aggiunge replyTo solo se la variabile d'ambiente è impostata
          ...(replyTo ? { replyTo } : {}), 
          subject: "Il tuo link al calcolatore",
          html: `<p>Ciao! Ecco il tuo link personale al calcolatore:</p>
                   <p><a href="${link}">${link}</a></p>
                   <p>Tentativi disponibili: <strong>${attempts}</strong></p>`,
        });
      } catch (e) {
        console.error("Errore invio email Resend:", e?.message || e);
      }
    }

    res.json({ received: true });
  }
);

/* ------------------------ 4. PARSER E LOGGING ------------------------ */
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use((req, res, next) => {
  if (req.path.startsWith("/api/")) {
    console.log("[api]", req.method, req.path, "body=", req.body);
  }
  next();
});


/* ------------------------ 5. STATICI ------------------------ */
app.use(
  "/public",
  express.static(path.join(__dirname, "public"), { index: false })
);
app.get("/", (_, res) => res.redirect("/public/index.html"));


/* ------------------------ 6. PRICE IDs (SOSTITUISCI con price_...) ------------------------ */
const PRICES = {
  "1": "price_1SGd2uFb9AZszxVCwrlU2Ooh",
  "3": "price_1SGdGIFb9AZszxVCpQyNIX3jF",
  "10": "price_1SGdHdFb9AZszxVCidfbEB4b",
};

/* ------------------------ 7. CONFIG PUBBLICA (PK) ------------------------ */
app.get("/api/public-config", (req, res) => {
  res.json({ stripePk: process.env.STRIPE_PUBLISHABLE_KEY || "" });
});

/* ------------------------ 8. PROMO CODE LOOKUP ------------------------ */
async function findPromotionCodeId(code) {
  if (!code) return null;
  const cleaned = String(code).trim();
  if (!cleaned) return null;
  const list = await stripe.promotionCodes.list({
    code: cleaned,
    active: true,
    limit: 1,
  });
  return list.data?.[0]?.id || null;
}


/* ------------------------ 9. CREATE CHECKOUT SESSION (UNICA VERSIONE) ------------------------ */
app.post("/api/create-checkout-session", async (req, res) => {
  const { email, pkg, promoCode } = req.body || {};
  if (!email || !PRICES[pkg]) {
    return res.status(400).json({ error: "Parametri non validi" });
  }
  const isEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  if (!isEmail) return res.status(400).json({ error: "Email non valida" });

  const priceId = PRICES[pkg];
  if (!priceId.startsWith("price_")) {
    return res.status(500).json({
      error:
        "ID nel mapping PRICES NON è un Price ID (sostituisci prod_... con price_...)",
    });
  }

  try {
    const discounts = [];
    if (promoCode && String(promoCode).trim()) {
      const promoId = await findPromotionCodeId(promoCode);
      if (!promoId) {
        return res
          .status(400)
          .json({ error: "Codice sconto non valido o non attivo" });
      }
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

/* ------------------------ 10. API TENTATIVI ------------------------ */
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

/* ------------------------ 11. ADMIN PROMO USAGE ------------------------ */
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
  try {
    list = (uses.result || []).map((x) => JSON.parse(x));
  } catch {}
  res.json({ code, count: Number(count.result || 0), recent: list });
});

/* ------------------------ 12. HANDLER ERRORE GLOBALE ------------------------ */
app.use((err, req, res, next) => {
  const status = err?.status || err?.statusCode || 500;
  const payload = {
    message: err?.message || "Server error",
    statusCode: status,
  };
  console.error("[global-error]", payload);
  res.status(status).json({ ok: false, error: payload });
});

/* ------------------------ 13. AVVIO ------------------------ */
const port = process.env.PORT || 4242;
app.listen(port, () => {
  console.log(
    `Server attivo su ${process.env.PUBLIC_BASE_URL || `http://localhost:${port}`}`
  );
});
