// Sostituisci TUTTA la funzione redisCommand con questa versione
async function redisCommand(...args) {
  if (!UPSTASH_URL || !UPSTASH_TOKEN) {
    throw new Error("Upstash URL/TOKEN mancanti");
  }
  if (!args.length) {
    throw new Error("redisCommand: nessun argomento");
  }

  // Upstash REST: usa "command": <string>, "args": [ ... ]
  const [cmd, ...rest] = args.map((a) => (a === undefined || a === null ? "" : String(a)));

  const resp = await compatFetch(UPSTASH_URL, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${UPSTASH_TOKEN}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ command: cmd, args: rest }),
  });

  const json = await resp.json().catch(() => ({}));
  if (!resp.ok || json?.error) {
    throw new Error(`Upstash error ${resp.status}: ${JSON.stringify(json)}`);
  }
  return json; // { result: ... }
}

// (NUOVO) endpoint rapido per testare Upstash dal runtime
app.get("/api/kv-test", async (req, res) => {
  try {
    const k = "kv:test:ping";
    const v = `ok-${Date.now()}`;
    // SET key v EX 60
    await redisCommand("SET", k, v, "EX", "60");
    const got = await redisCommand("GET", k);
    res.json({ ok: true, set: v, get: got?.result ?? null });
  } catch (e) {
    console.error("[kv-test] error:", e?.message || e);
    res.status(500).json({ ok: false, error: e?.message || String(e) });
  }
});
