import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

const E = process.env;
const STAFF = { president: E.PRESI_COHASARKAF, secretaire: E.SG_COHASARKAF, tresorier: E.TRESORIER_COHASARKAF };
const json = (o, s = 200, h = {}) =>
  new Response(JSON.stringify(o), { status: s, headers: { "content-type": "application/json", "cache-control": "no-store", ...h } });
const mac = (s) => crypto.createHmac("sha256", E.SESSION_SECRET || "").update(s).digest("base64url");
const sha = (s) => crypto.createHash("sha256").update(String(s)).digest();
const eq = (a, b) => crypto.timingSafeEqual(sha(a), sha(b));
const cookie = (v, age) => `sid=${v}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${age}`;
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
const hashPw = (pw, salt) => crypto.scryptSync(pw, salt, 32).toString("hex");
const normTel = (t) => String(t || "").replace(/\D/g, "").slice(-9);

function token(me) {
  const p = Buffer.from(JSON.stringify({ id: me.id, role: me.role, exp: Date.now() + 12 * 3600e3 })).toString("base64url");
  return p + "." + mac(p);
}
function who(req) {
  const m = /(?:^|;\s*)sid=([^;]+)/.exec(req.headers.get("cookie") || "");
  if (!m) return null;
  const [p, s] = m[1].split(".");
  if (!p || !s || !eq(mac(p), s)) return null;
  try {
    const d = JSON.parse(Buffer.from(p, "base64url").toString());
    return d.exp > Date.now() ? d : null;
  } catch { return null; }
}
const session = (me) => json({ id: me.id, role: me.role }, 200, { "set-cookie": cookie(token(me), 43200) });

export default async (req) => {
  if (!E.SESSION_SECRET || E.SESSION_SECRET.length < 24) return json({ error: "Configuration incomplète : SESSION_SECRET manquant." }, 500);
  const path = new URL(req.url).pathname.replace(/^\/api\//, "");
  const S = getStore({ name: "cohasar", consistency: "strong" });
  const post = req.method === "POST";
  try {
    if (path === "logout") return json({ ok: true }, 200, { "set-cookie": cookie("", 0) });

    if (path === "register" && post) {
      const b = await req.json(), tel = normTel(b.tel), pw = String(b.password || "");
      if (tel.length !== 9) return json({ error: "Numéro de téléphone invalide (9 chiffres)." }, 400);
      if (pw.length < 8) return json({ error: "Mot de passe : 8 caractères minimum." }, 400);
      if (await S.get("u:" + tel, { type: "json" })) return json({ error: "Ce numéro a déjà un compte. Connectez-vous." }, 409);
      const salt = crypto.randomBytes(16).toString("hex");
      const id = "a" + crypto.createHash("sha1").update(tel).digest("hex").slice(0, 14);
      await S.setJSON("u:" + tel, { id, salt, h: hashPw(pw, salt), d: new Date().toISOString() });
      return session({ id, role: "agent" });
    }

    if (path === "login" && post) {
      const b = await req.json(), pw = String(b.password || "");
      if (Object.hasOwn(STAFF, b.id)) {
        if (STAFF[b.id] && eq(pw, STAFF[b.id])) return session({ id: b.id, role: b.id });
        await wait(800);
        return json({ error: "Identifiant ou mot de passe incorrect." }, 401);
      }
      const u = await S.get("u:" + normTel(b.id), { type: "json" });
      if (u && eq(hashPw(pw, u.salt), u.h)) return session({ id: u.id, role: "agent" });
      await wait(800);
      return json({ error: "Téléphone ou mot de passe incorrect." }, 401);
    }

    const me = who(req);
    if (!me) return json({ error: "Non connecté." }, 401);
    if (path === "me") return json({ id: me.id, role: me.role });

    if (path === "upload" && post) {
      const b = await req.json();
      const type = /^(image\/(jpeg|png|webp)|application\/pdf)$/.test(b.type) ? b.type : null;
      if (!type) return json({ error: "Format non accepté (JPG, PNG ou PDF)." }, 415);
      const buf = Buffer.from(String(b.data || ""), "base64");
      if (!buf.length || buf.length > 4e6) return json({ error: "Fichier trop volumineux (4 Mo maximum)." }, 413);
      const id = crypto.randomBytes(16).toString("hex");
      await S.set("f:" + id, buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength), { metadata: { owner: me.id, type } });
      return json({ id });
    }

    if (path.startsWith("file/")) {
      const id = path.slice(5);
      if (!/^[a-f0-9]{32}$/.test(id)) return json({ error: "Introuvable." }, 404);
      const f = await S.getWithMetadata("f:" + id, { type: "arrayBuffer" });
      if (!f) return json({ error: "Introuvable." }, 404);
      if (me.role === "tresorier" || (me.role === "agent" && f.metadata.owner !== me.id)) return json({ error: "Accès refusé." }, 403);
      return new Response(f.data, { headers: { "content-type": f.metadata.type, "cache-control": "private, no-store", "content-disposition": "inline" } });
    }

    if (path === "db" && post) return await db(S, me, await req.json());
    return json({ error: "Introuvable." }, 404);
  } catch (e) {
    return json({ error: "Erreur du serveur." }, 500);
  }
};

async function db(S, me, b) {
  const [col, id] = String(b.path || "").split("/");
  const R = me.role;
  const deny = () => json({ error: "Accès refusé." }, 403);
  const key = (i) => "d:" + col + "/" + i;

  if (col === "config") {
    if (b.op === "get" && id === "roles") return json({ exists: true, data: { secretaire: "secretaire", tresorier: "tresorier" } });
    return b.op === "get" ? json({ exists: false }) : deny();
  }
  if (col === "demandes") return b.op === "list" ? json({ docs: [] }) : b.op === "get" ? json({ exists: false }) : deny();
  if (col !== "inscriptions" && col !== "cotisations") return deny();
  if (col === "cotisations" && R !== "president" && R !== "tresorier") return deny();

  if (b.op === "list") {
    if (col === "inscriptions" && R === "agent") return deny();
    const { blobs } = await S.list({ prefix: "d:" + col + "/" });
    let docs = [];
    for (const x of blobs) {
      const d = await S.get(x.key, { type: "json" });
      if (d) docs.push({ id: x.key.split("/")[1], data: d });
    }
    if (col === "inscriptions" && R === "tresorier")
      docs = docs.filter((x) => x.data.etat === "valide").map((x) => ({
        id: x.id, data: { prenom: x.data.prenom, nom: x.data.nom, num: x.data.num, etat: x.data.etat, date: x.data.date },
      }));
    return json({ docs });
  }

  if (!id || !/^[A-Za-z0-9_-]{1,40}$/.test(id)) return deny();
  const cur = await S.get(key(id), { type: "json" });

  if (b.op === "get") {
    if (col === "inscriptions" && !(R === "president" || R === "secretaire" || (R === "agent" && id === me.id))) return deny();
    return json(cur ? { exists: true, data: cur } : { exists: false });
  }
  if (b.op !== "set" && b.op !== "update") return deny();
  const data = b.data && typeof b.data === "object" ? b.data : {};
  if (JSON.stringify(data).length > 60000) return json({ error: "Données trop volumineuses." }, 413);
  const save = async (d) => { await S.setJSON(key(id), d); return json({ ok: true }); };
  const merged = b.op === "update" ? { ...cur, ...data } : data;

  if (col === "cotisations") return save(merged);

  if (R === "agent") {
    if (id !== me.id || b.op !== "set") return deny();
    if (cur && cur.etat === "valide") return json({ error: "Dossier déjà validé : contactez le bureau." }, 403);
    const nd = { ...data };
    for (const k of ["etat", "num", "avis", "decby", "dec", "msgs", "motif"]) {
      if (cur && cur[k] !== undefined) nd[k] = cur[k]; else delete nd[k];
    }
    nd.etat = (cur && cur.etat) || "recu";
    nd.date = (cur && cur.date) || new Date().toISOString();
    return save(nd);
  }
  if (R === "president") return save(merged);
  if (R === "secretaire" && b.op === "update" && cur) {
    const nd = { ...cur };
    if (data.avis) nd.avis = { ...data.avis, by: me.id };
    if (Array.isArray(data.msgs)) nd.msgs = data.msgs;
    if (data.etat === "examen" && cur.etat === "recu") nd.etat = "examen";
    return save(nd);
  }
  return deny();
}

export const config = { path: "/api/*" };
