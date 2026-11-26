/* TPP Report Builder vault.
   The app is stored encrypted (AES-GCM, random 256-bit key K).
   Each user has an RSA-OAEP key pair. Their private key is encrypted with a key
   derived from their password (PBKDF2-SHA256). K is encrypted to each user's public key,
   so an admin can add, remove or reset users and rotate K without knowing anyone else's password. */
(function (g) {
  const C = g.crypto.subtle, enc = new TextEncoder(), dec = new TextDecoder();
  const ITER = 600000;
  const b64 = u => { u = new Uint8Array(u); let s = ""; for (let i = 0; i < u.length; i += 8192) s += String.fromCharCode.apply(null, u.subarray(i, i + 8192)); return btoa(s); };
  const ub64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  const rand = n => g.crypto.getRandomValues(new Uint8Array(n));
  const norm = n => String(n || "").trim().toLowerCase();
  async function userId(name) { return b64(await C.digest("SHA-256", enc.encode("tpp-user|" + norm(name)))).replace(/[^a-z0-9]/gi, "").slice(0, 32); }
  async function pwKey(pw, salt) { const k = await C.importKey("raw", enc.encode(pw), "PBKDF2", false, ["deriveKey"]); return C.deriveKey({ name: "PBKDF2", hash: "SHA-256", salt, iterations: ITER }, k, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]); }
  async function aesKey(raw) { return C.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]); }
  async function seal(key, bytes) { const iv = rand(12); return { iv: b64(iv), ct: b64(await C.encrypt({ name: "AES-GCM", iv }, key, bytes)) }; }
  async function unseal(key, o) { return new Uint8Array(await C.decrypt({ name: "AES-GCM", iv: ub64(o.iv) }, key, ub64(o.ct))); }
  const RSA = { name: "RSA-OAEP", modulusLength: 3072, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" };

  // Create a user entry (key pair, private key locked with their password).
  async function makeUser(name, pw) {
    const kp = await C.generateKey(RSA, true, ["encrypt", "decrypt"]);
    const salt = rand(16);
    const pk = await seal(await pwKey(pw, salt), await C.exportKey("pkcs8", kp.privateKey));
    return { id: await userId(name), pub: b64(await C.exportKey("spki", kp.publicKey)), salt: b64(salt), pk };
  }
  // Build a fresh vault with a new random K. users: {id: {pub, salt, pk}}, dir: [{name, role, id}]
  async function build(appHtml, dir, users) {
    const raw = rand(32), K = await aesKey(raw), out = { v: 1, app: await seal(K, enc.encode(appHtml)), dir: await seal(K, enc.encode(JSON.stringify(dir))), users: {} };
    for (const [id, u] of Object.entries(users)) {
      const pub = await C.importKey("spki", ub64(u.pub), RSA, false, ["encrypt"]);
      out.users[id] = { pub: u.pub, salt: u.salt, pk: u.pk, wk: b64(await C.encrypt({ name: "RSA-OAEP" }, pub, raw)) };
    }
    return out;
  }
  // Log in: returns {raw K, app, dir, id} or throws.
  async function open(vault, name, pw) {
    const id = await userId(name), u = vault.users[id];
    if (!u) throw new Error("bad");
    const pkcs8 = await unseal(await pwKey(pw, ub64(u.salt)), u.pk);
    const priv = await C.importKey("pkcs8", pkcs8, RSA, false, ["decrypt"]);
    const raw = new Uint8Array(await C.decrypt({ name: "RSA-OAEP" }, priv, ub64(u.wk)));
    return { raw: b64(raw), id, ...(await withKey(vault, b64(raw))) };
  }
  // Reopen with a saved session key (no password needed in the same tab).
  async function withKey(vault, rawB64) {
    const K = await aesKey(ub64(rawB64));
    return { app: dec.decode(await unseal(K, vault.app)), dir: JSON.parse(dec.decode(await unseal(K, vault.dir))) };
  }
  g.TPPVault = { makeUser, build, open, withKey, userId, norm };
})(globalThis);
