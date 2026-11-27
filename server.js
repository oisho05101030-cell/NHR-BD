const https = require("https");
// NHR BD Server (Node.js + Express + Nodemailer)
// Run: npm install express nodemailer dotenv
// Start: node server.js

require("dotenv").config();
const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const nodemailer = require("nodemailer");

process.on("unhandledRejection", (e) => console.error("Unhandled error:", e));

/* ================= CONFIGURATIONS ================= */
const PORT = process.env.PORT || 5000;
const PUBLIC_URL = (process.env.PUBLIC_URL || "").replace(/\/+$/, "");

// Gmail Transporter (HTTPS Apps Script Webhook + SMTP Fallback with strict timeout)
const transporter = nodemailer.createTransport({
  service: "gmail",
  connectionTimeout: 6000,
  greetingTimeout: 6000,
  socketTimeout: 6000,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

function postJsonIpv4(targetUrl, payload, redirectsLeft = 3) {
  return new Promise((resolve, reject) => {
    const u = new URL(targetUrl);
    const data = JSON.stringify(payload);
    const req = https.request({
      hostname: u.hostname,
      port: u.port || 443,
      path: u.pathname + u.search,
      method: "POST",
      family: 4,
      timeout: 9000,
      headers: {
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(data)
      }
    }, (res) => {
      if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location && redirectsLeft > 0) {
        res.resume();
        const nextUrl = new URL(res.headers.location, targetUrl).toString();
        const getReq = https.get(nextUrl, { family: 4, timeout: 9000 }, (gRes) => {
          let body = "";
          gRes.on("data", (c) => body += c);
          gRes.on("end", () => resolve({ status: gRes.statusCode, body }));
        });
        getReq.on("timeout", () => { getReq.destroy(new Error("redirect_timeout")); });
        getReq.on("error", reject);
        return;
      }
      let body = "";
      res.on("data", (c) => body += c);
      res.on("end", () => resolve({ status: res.statusCode, body }));
    });
    req.on("timeout", () => { req.destroy(new Error("webhook_timeout")); });
    req.on("error", reject);
    req.write(data);
    req.end();
  });
}

async function deliverEmail({ to, subject, html }) {
  if (!to) return false;
  const webhook = s(process.env.GMAIL_WEBHOOK_URL);
  if (webhook) {
    try {
      const r = await postJsonIpv4(webhook, { to, subject, html });
      if (r.status >= 200 && r.status < 300 && /ok/i.test(r.body)) return true;
      console.error("❌ Gmail Webhook Error:", r.status, r.body.slice(0, 200));
      return false;
    } catch (err) {
      console.error("❌ Gmail Webhook Net Error:", err.message || err);
      return false;
    }
  }
  try {
    await Promise.race([
      transporter.sendMail({
        from: `"NHR BD Portal" <${process.env.EMAIL_USER}>`,
        to,
        subject,
        html,
      }),
      new Promise((_, rej) => setTimeout(() => rej(new Error("smtp_timeout")), 8000))
    ]);
    return true;
  } catch (err) {
    console.error("❌ SMTP Email Error:", err.message || err);
    return false;
  }
}

const ADMINS = [
  { id: "ADM00000001", name: "Admin", password: "Admin@0001" }
];
const AUTO_VERIFY_DOCTORS = false;
/* =================================================== */

/* ---------- Database (JSON file) ---------- */
const DB_FILE = path.join(__dirname, "db.json");
let db = { users: [], credentials: [], records: [], audit: [], facilities: [] };
try { db = Object.assign(db, JSON.parse(fs.readFileSync(DB_FILE, "utf8"))); } catch (e) { /* first run */ }
const save = () => fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));

// blood donor / request / stock / notification data Initialization
db.notifs = db.notifs || {};
db.donorViews = db.donorViews || [];
db.bloodRequests = db.bloodRequests || [];
db.bloodStock = db.bloodStock || {};

/* ---------- Helpers ---------- */
const b64u = { enc: (b) => Buffer.from(b).toString("base64url"), dec: (s) => Buffer.from(String(s), "base64url") };
const sha256 = (b) => crypto.createHash("sha256").update(b).digest();
const rand = (n) => crypto.randomBytes(n);
const s = (v) => String(v == null ? "" : v).trim();
const he = (v) => String(v == null ? "" : v).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
if (!db.secret) { db.secret = rand(32).toString("hex"); save(); }

function hashPw(pw) { const salt = rand(16); return salt.toString("hex") + ":" + crypto.scryptSync(pw, salt, 64).toString("hex"); }
function checkPw(pw, stored) {
  const [salt, hash] = String(stored).split(":");
  if (!salt || !hash) return false;
  const a = crypto.scryptSync(pw, Buffer.from(salt, "hex"), 64), b = Buffer.from(hash, "hex");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
const adminHash = {};
ADMINS.forEach((a) => { adminHash[a.id] = hashPw(a.password); });

function ageOf(dob) {
  const d = new Date(dob), n = new Date();
  let a = n.getFullYear() - d.getFullYear();
  if (n < new Date(n.getFullYear(), d.getMonth(), d.getDate())) a--;
  return a;
}
const nidInRange = (n) => Number(n) >= 692410005101001 && Number(n) <= 692410005101050;
const bad = (res, error, code = 400, extra = {}) => res.status(code).json(Object.assign({ error }, extra));
const hostOf = (req) => String(req.get("x-forwarded-host") || req.get("host") || "").split(",")[0].trim();
const isLocal = (h) => !h || /^localhost(?::|$)|^127\.0\.0\.1(?::|$)/.test(h);
const originOf = (req) => { const h = hostOf(req); return !isLocal(h) ? (String(req.get("x-forwarded-proto") || "https").split(",")[0].trim() + "://" + h) : (PUBLIC_URL || "http://" + h); };
const clientOrigin = (req) => { const o = s(req.get("origin")); return /^https?:\/\/[a-z0-9.-]+(?::\d+)?$/i.test(o) ? o : originOf(req); };
const baseOf = (req) => clientOrigin(req);
const rpHostOf = (req) => new URL(clientOrigin(req)).hostname;

function newNhrId() {
  let id;
  do { id = String(1 + Math.floor(Math.random() * 9)); for (let i = 0; i < 11; i++) id += Math.floor(Math.random() * 10); }
  while (db.users.some((u) => u.nhrId === id));
  return id;
}

/* ---------- Email Notification Helper Functions ---------- */
async function sendOtpEmail(toEmail, patientName, otpCode) {
  if (!toEmail) return false;
  const mailOptions = {
    from: `"NHR BD Portal" <${process.env.EMAIL_USER}>`,
    to: toEmail,
    subject: `[NHR BD] Security Verification OTP: ${s(otpCode).replace(/[^0-9]/g, "")}`,
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 500px; padding: 20px; border: 1px solid #d9e5f0; border-radius: 12px; background: #f4faff;">
        <h2 style="color: #0c3b5e; margin-bottom: 5px;">National Health Record (NHR BD)</h2>
        <p style="color: #5b6b80; font-size: 14px;">আপনার স্বাস্থ্য রেকর্ড দেখার জন্য নিরাপত্তা ওটিপি (OTP):</p>
        <div style="background: #0a8fc7; color: #ffffff; font-size: 28px; font-weight: bold; text-align: center; padding: 12px; border-radius: 8px; letter-spacing: 6px; margin: 15px 0;">
          ${he(otpCode)}
        </div>
        <p style="color: #5b6b80; font-size: 13px;">প্রিয় <b>${he(patientName) || 'রোগী'}</b>, এই কোডটি ৫ মিনিটের জন্য কার্যকর থাকবে। এটি কারও সাথে শেয়ার করবেন না।</p>
      </div>
    `
  };
  const ok = await deliverEmail({ to: mailOptions.to, subject: mailOptions.subject, html: mailOptions.html });
  if (ok) console.log(`✅ OTP email sent to ${toEmail}`);
  return ok;
}

async function sendEmergencyAlertEmail(toEmail, patientName, doctorName, hospitalName, reason, timestamp) {
  if (!toEmail) return false;
  const mailOptions = {
    to: toEmail,
    subject: `🚨 [EMERGENCY ACCESS ALERT] Medical Record Accessed!`,
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 550px; padding: 20px; border: 2px solid #d92d3a; border-radius: 12px; background: #fff1f2;">
        <h2 style="color: #d92d3a; margin-top: 0;">🚨 জরুরি স্বাস্থ্য ডাটা অ্যাক্সেস সতর্কতা!</h2>
        <p style="font-size: 14px; color: #1b2d42;">প্রিয় <b>${he(patientName) || 'রোগী'}</b>,</p>
        <p style="font-size: 14px; color: #5b6b80; line-height: 1.5;">
          জরুরি অবস্থায় আপনার উপস্থিতি/সম্মতি ছাড়া একজন নিবন্ধিত চিকিৎসক আপনার ফাইল ওভাররাইড করে খুলেছেন।
        </p>
        <table style="width: 100%; border-collapse: collapse; margin: 15px 0; background: #ffffff; border-radius: 8px; border: 1px solid #e3edf5;">
          <tr><td style="padding: 8px; font-weight: bold; color: #0c3b5e; border-bottom: 1px solid #edf3f8;">ডাক্তারের নাম:</td><td style="padding: 8px; border-bottom: 1px solid #edf3f8;">${he(doctorName)}</td></tr>
          <tr><td style="padding: 8px; font-weight: bold; color: #0c3b5e; border-bottom: 1px solid #edf3f8;">হাসপাতাল/চেম্বার:</td><td style="padding: 8px; border-bottom: 1px solid #edf3f8;">${he(hospitalName)}</td></tr>
          <tr><td style="padding: 8px; font-weight: bold; color: #0c3b5e; border-bottom: 1px solid #edf3f8;">অ্যাক্সেসের কারণ:</td><td style="padding: 8px; color: #d92d3a; border-bottom: 1px solid #edf3f8;">${he(reason)}</td></tr>
          <tr><td style="padding: 8px; font-weight: bold; color: #0c3b5e;">সময়:</td><td style="padding: 8px;">${he(timestamp)}</td></tr>
        </table>
        <p style="font-size: 12px; color: #8e1d27;">এটি অনাকাঙ্ক্ষিত হলে অবিলম্বে NHR Support-এ রিপোর্ট করুন।</p>
      </div>
    `
  };
  const ok = await deliverEmail({ to: mailOptions.to, subject: mailOptions.subject, html: mailOptions.html });
  if (ok) console.log(`🚨 Emergency Alert email sent to ${toEmail}`);
  return ok;
}

/* ---------- App Initialization ---------- */
const app = express();
app.use((req, res, next) => {
  const origin = req.get("origin");
  if (origin) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type,Authorization");
  }
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});
app.set("trust proxy", true);
app.use(express.json({ limit: "100kb" }));
app.use(express.static(path.join(__dirname, "public")));
app.get("/", (req, res) => res.redirect("/login.html"));

/* ---------- Registration ---------- */
const enrollKeys = new Map();
const norm = (x) => s(x).toLowerCase().replace(/\s+/g, " ");

app.post("/api/register", (req, res) => {
  const d = req.body || {}, e = d.emergency || {}, dc = d.doctor || {};
  const nid = s(d.nid), phone = s(d.phone), dob = s(d.dob), pw = String(d.password || "");
  const wantDoctor = d.role === "doctor" && !!d.doctor;
  const wantPatient = d.role !== "doctor" || d.createPatient === true;
  const phoneOk = (v) => /^01[3-9]\d{8}$/.test(v);

  if (s(d.fullName).length < 3) return bad(res, "eName");
  if (s(d.fatherName).length < 2) return bad(res, "eFather");
  if (s(d.motherName).length < 2) return bad(res, "eMother");
  if (!dob || isNaN(new Date(dob)) || ageOf(dob) < 18) return bad(res, "eMinor");
  if (!["Male", "Female", "Other"].includes(s(d.gender))) return bad(res, "eGender");
  if (!/^\d{16}$/.test(nid) || !nidInRange(nid)) return bad(res, "eNidInvalid");
  if (!phoneOk(phone)) return bad(res, "ePhone");
  if (s(d.email) && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s(d.email))) return bad(res, "eEmail");
  if (!s(d.division)) return bad(res, "eDiv");
  if (!s(d.district)) return bad(res, "eDist");
  if (s(d.address).length < 5) return bad(res, "eAddr");
  if (wantPatient) {
    if (!["A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-"].includes(s(d.bloodGroup))) return bad(res, "eBlood");
    if (s(e.name).length < 3) return bad(res, "eEmName");
    if (!s(e.relation)) return bad(res, "eEmRel");
    if (!phoneOk(s(e.phone))) return bad(res, "ePhone");
    if (s(e.phone) === phone) return bad(res, "eEmSame");
    if (pw.length < 8) return bad(res, "ePwLen");
  }
  const lic = s(dc.license).toUpperCase();
  if (d.role === "doctor") {
    if (!wantDoctor || !/^DOC\d{8}$/.test(lic)) return bad(res, "eLic");
    if (s(dc.speciality).length < 2) return bad(res, "eSpec");
    if (s(dc.hospital).length < 2) return bad(res, "eHosp");
    if (String(dc.password || "").length < 8) return bad(res, "ePwLen");
    if (wantPatient && String(dc.password) === pw) return bad(res, "eDocPwSame");
  }
  if (!d.consent) return bad(res, "eConsent");

  const ex = db.users.find((u) => u.nid === nid);
  const other = db.users.find((u) => u.phone === phone);
  if (other && other !== ex) return bad(res, "dupPhone", 409);
  if (wantDoctor && db.users.some((u) => u !== ex && u.doctor && u.doctor.license === lic)) return bad(res, "dupLic", 409);

  let user = ex, addPatient = wantPatient, addDoctor = wantDoctor;
  if (ex) {
    const hasPat = ex.patientActive !== false;
    addPatient = wantPatient && !hasPat;
    addDoctor = wantDoctor && !ex.doctor;
    if (!addPatient && !addDoctor) return bad(res, wantDoctor && !wantPatient ? "dupDocNid" : "dupNid", 409);
    if (norm(ex.fullName) !== norm(d.fullName) || ex.dob !== dob || ex.phone !== phone) return bad(res, "idMismatch", 409);
    const lk = "link:" + nid, m = lockMin(lk);
    if (m) return bad(res, "locked", 429, { m });
    const lp = String(d.linkPassword || "");
    if (!lp) return bad(res, "linkNeeded", 409);
    if (!checkPw(lp, hasPat ? ex.passwordHash : ex.doctor.passwordHash)) {
      const left = addFail(lk);
      return left ? bad(res, "wrongLink", 401, { left }) : bad(res, "locked", 429, { m: 5 });
    }
    fails.delete(lk);
  }

  if (!user) {
    user = {
      nhrId: newNhrId(), fullName: s(d.fullName), fatherName: s(d.fatherName), motherName: s(d.motherName),
      dob, gender: s(d.gender), nid, bloodGroup: "", phone, email: s(d.email),
      division: s(d.division), district: s(d.district), address: s(d.address),
      emergency: {}, role: "patient", passwordHash: null, patientActive: false, consentGiven: true, createdAt: new Date().toISOString()
    };
    db.users.push(user);
  }
  if (addPatient) Object.assign(user, { bloodGroup: s(d.bloodGroup), emergency: { name: s(e.name), relation: s(e.relation), phone: s(e.phone) }, passwordHash: hashPw(pw), patientActive: true, status: "active" });
  if (addDoctor) user.doctor = { license: lic, speciality: s(dc.speciality), hospital: s(dc.hospital), status: AUTO_VERIFY_DOCTORS ? "verified" : "pending", passwordHash: hashPw(String(dc.password)) };
  save();

  let key;
  if (addPatient) { key = rand(16).toString("hex"); enrollKeys.set(nid, { key, exp: Date.now() + 15 * 60000 }); }
  res.json({ ok: true, nhrId: user.patientActive !== false ? user.nhrId : undefined, doctorId: user.doctor ? user.doctor.license : undefined, doctorPending: addDoctor && user.doctor.status !== "verified", enrollKey: key });
});

/* ---------- Sign in ---------- */
const sessions = new Map();
const makeSession = (a) => { const token = rand(24).toString("hex"); sessions.set(token, { type: a.type, name: a.name, nhrId: a.nhrId, at: Date.now() }); return token; };

function lookup(id) {
  const adm = ADMINS.find((x) => x.id === id);
  if (adm) return { type: "admin", name: adm.name, nhrId: adm.id, hash: adminHash[adm.id] };
  if (/^ADM\d{8}$/.test(id)) return null;
  if (/^FAC\d{8}$/.test(id)) { const f = db.facilities.find((x) => x.id === id); return f ? { type: "facility", user: f, name: f.name, nhrId: f.id, hash: f.passwordHash } : null; }
  if (/^DOC\d{8}$/.test(id)) { const u = db.users.find((x) => x.doctor && x.doctor.license === id); return u ? { type: "doctor", user: u, name: u.fullName, nhrId: u.nhrId, hash: u.doctor.passwordHash } : null; }
  if (/^B\d{8}$/.test(id)) { const u = db.users.find((x) => x.brn === id); return u ? { type: "brn", user: u, name: u.fullName, nhrId: u.nhrId, hash: u.passwordHash } : null; }
  if (/^\d{16}$/.test(id)) {
    const u = db.users.find((x) => x.nid === id);
    if (!u) return null;
    if (u.patientActive === false) return { type: "nopatient" };
    return { type: "nid", user: u, name: u.fullName, nhrId: u.nhrId, hash: u.passwordHash };
  }
  return null;
}

const fails = new Map();
const lockMin = (k) => { const f = fails.get(k); return f && f.until > Date.now() ? Math.ceil((f.until - Date.now()) / 60000) : 0; };
function addFail(k) {
  const f = fails.get(k) || { n: 0, until: 0 };
  f.n++;
  if (f.n >= 5) { f.until = Date.now() + 5 * 60000; f.n = 0; }
  fails.set(k, f);
  return f.until > Date.now() ? 0 : 5 - f.n;
}

app.post("/api/login", (req, res) => {
  const id = s(req.body && req.body.id).toUpperCase(), pw = String((req.body && req.body.password) || "");
  const acc = lookup(id);
  if (!acc) return bad(res, "noUser", 404);
  if (acc.type === "nopatient") return bad(res, "noPatient", 404);
  const m = lockMin(id);
  if (m) return bad(res, "locked", 429, { m });
  if (acc.type === "doctor") {
    const st = acc.user.doctor.status;
    if (st !== "verified") return bad(res, st === "rejected" ? "rejectedDoc" : st === "suspended" ? "suspendedDoc" : "pendingDoc", 403);
  }
  if (acc.type === "facility" && acc.user.status !== "active") return bad(res, "suspendedFac", 403);
  if (acc.type === "brn" && acc.user.dob && ageOf(acc.user.dob) >= 18) return bad(res, "adult", 403);
  if (!checkPw(pw, acc.hash)) {
    const left = addFail(id);
    return left ? bad(res, "wrongPw", 401, { left }) : bad(res, "locked", 429, { m: 5 });
  }
  fails.delete(id);
  const u = acc.user, out = { type: acc.type, name: acc.name, nhrId: acc.nhrId };
  if (acc.type === "doctor") { out.doctorId = u.doctor.license; out.linkedNid = u.patientActive !== false ? u.nid : null; }
  if (acc.type === "nid" || acc.type === "brn") { if (u.doctor) out.doctorId = u.doctor.license; reactivate(u); }
  res.json({ ok: true, token: makeSession(acc), user: out });
});

app.get("/api/me", (req, res) => {
  const x = getSes(req);
  return x ? res.json({ ok: true, user: { type: x.type, name: x.name, nhrId: x.nhrId } }) : bad(res, "noSession", 401);
});

app.get("/api/mail-status", (req, res) => {
  const wh = s(process.env.GMAIL_WEBHOOK_URL);
  res.json({
    hasWebhook: /^https:\/\//.test(wh),
    webhookHost: wh ? new URL(wh).hostname : null,
    hasSmtp: !!(s(process.env.EMAIL_USER) && s(process.env.EMAIL_PASS))
  });
});

/* ---------- Email endpoints ---------- */
app.post("/api/send-otp-email", async (req, res) => {
  const x = getSes(req); if (!x) return bad(res, "noSession", 401);
  if (limited("mail:" + x.nhrId, 10, 3600000)) return bad(res, "tooMany", 429);
  const { toEmail, patientName, otpCode } = req.body || {};
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s(toEmail)) || !/^\d{6}$/.test(s(otpCode))) return bad(res, "serverErr");
  const sent = await sendOtpEmail(s(toEmail), patientName, s(otpCode));
  return sent ? res.json({ ok: true }) : bad(res, "failed", 500);
});

app.post("/api/send-emergency-alert", async (req, res) => {
  const x = docSes(req); if (!x) return bad(res, "noSession", 401);
  if (limited("mail:" + x.nhrId, 10, 3600000)) return bad(res, "tooMany", 429);
  const { toEmail, patientName, hospitalName, reason, timestamp } = req.body || {};
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s(toEmail))) return bad(res, "serverErr");
  const sent = await sendEmergencyAlertEmail(s(toEmail), s(patientName).slice(0, 80), x.u.fullName, s(hospitalName).slice(0, 120) || x.u.doctor.hospital, s(reason).slice(0, 300), timestamp || new Date().toLocaleString());
  return sent ? res.json({ ok: true }) : bad(res, "failed", 500);
});

/* ---------- Phone Fingerprint (WebAuthn) ---------- */
const tickets = new Map();
function newTicket(data) {
  const id = rand(16).toString("hex");
  const t = Object.assign({ id, status: "pending", challenge: b64u.enc(rand(32)), exp: Date.now() + 5 * 60000 }, data);
  tickets.set(id, t);
  return t;
}
function getTicket(id) {
  const t = tickets.get(id);
  if (!t) return null;
  if (t.exp < Date.now()) { tickets.delete(id); return null; }
  return t;
}
const goodPoll = (v) => typeof v === "string" && /^[a-f0-9]{16,64}$/.test(v);

function ensureFb(f){if(!f)return null;const nid=String(f.nid||"").replace(/\D/g,""),nhrId=s(f.nhrId),uid=s(f.uid);if(!/^\d{16}$/.test(nid)&&!nhrId&&!uid)return null;let u=db.users.find(v=>(/^\d{16}$/.test(nid)&&v.nid===nid)||(nhrId&&v.nhrId===nhrId)||(uid&&v.uid===uid));if(!u){u={nhrId:nhrId||"NHR-"+Math.random().toString(36).slice(2,11).toUpperCase(),nid:/^\d{16}$/.test(nid)?nid:"",fullName:s(f.fullName)||"NHR User",email:s(f.email),uid,patientActive:true};db.users.push(u)}else{if(/^\d{16}$/.test(nid)&&!u.nid)u.nid=nid;if(uid)u.uid=uid;if(f.email)u.email=s(f.email);if(f.fullName)u.fullName=s(f.fullName)}if(typeof save==="function")save();return u}
app.post("/api/fp/ticket",(req,res)=>{const{nid,key,pollKey,lang,fbUser}=req.body||{};if(!goodPoll(pollKey))return bad(res,"serverErr",403);let u=fbUser?ensureFb(fbUser):null;if(!u){const k=enrollKeys.get(s(nid));if(!k||k.exp<Date.now()||k.key!==key)return bad(res,"serverErr",403);u=db.users.find(v=>v.nid===s(nid))}if(!u)return bad(res,"noUser",404);const t=newTicket({purpose:"enroll",userId:u.nhrId,name:u.fullName,pollKey,lang:lang==="bn"?"bn":"en"});res.json({ticket:t.id,base:baseOf(req)})});

app.post("/api/fp/session-ticket",(req,res)=>{const{pollKey,lang,fbUser}=req.body||{};if(!goodPoll(pollKey))return bad(res,"serverErr");let u=fbUser?ensureFb(fbUser):null;if(!u){const x=getSes(req);if(!x||x.type!=="nid")return bad(res,"noSession",401);u=db.users.find(v=>v.nhrId===x.nhrId)}if(!u)return bad(res,"noUser",404);const t=newTicket({purpose:"enroll",userId:u.nhrId,name:u.fullName,pollKey,lang:lang==="bn"?"bn":"en"});res.json({ticket:t.id,base:baseOf(req)})});

app.post("/api/fp/login-ticket",(req,res)=>{if(req.body&&req.body.fbUser)ensureFb(req.body.fbUser);
  const { id, pollKey, lang } = req.body || {};
  if (!/^\d{16}$/.test(s(id)) || !goodPoll(pollKey)) return bad(res, "fpNidOnly");
  const user = db.users.find((u) => u.nid === s(id));
  if (!user) return bad(res, "noUser", 404);
  if (user.patientActive === false) return bad(res, "noPatient", 404);
  const creds = db.credentials.filter((c) => c.userId === user.nhrId);
  if (!creds.length) return bad(res, "fpNone", 404);
  const hostCreds = creds.filter((c) => c.rpId === rpHostOf(req));
  if (!hostCreds.length) return bad(res, "fpOtherHost", 409);
  const t = newTicket({ purpose: "login", userId: user.nhrId, name: user.fullName, credentialId: hostCreds[0].credentialId, credentialIds: hostCreds.map(c => c.credentialId), pollKey, lang: lang === "bn" ? "bn" : "en" });
  res.json({ ticket: t.id, base: baseOf(req) });
});

app.get("/api/fp/ticket/:id", (req, res) => {
  const t = getTicket(req.params.id);
  if (!t) return bad(res, "expired", 404);
  res.json({
    purpose: t.purpose, status: t.status, name: t.name, lang: t.lang, challenge: t.challenge,
    userHandle: b64u.enc(Buffer.from(t.userId)), label: "NHR " + t.userId.slice(-4), credentialId: t.credentialId || null, credentialIds: t.credentialIds || (t.credentialId ? [t.credentialId] : [])
  });
});

app.post("/api/fp/ticket/:id/enroll", (req, res) => {
  const t = getTicket(req.params.id);
  if (!t || t.purpose !== "enroll") return bad(res, "expired", 404);
  if (t.status !== "pending") return bad(res, "used", 409);
  try {
    const b = req.body || {};
    const cd = JSON.parse(b64u.dec(b.clientDataJSON).toString("utf8"));
    if (cd.type !== "webauthn.create" || cd.challenge !== t.challenge || cd.origin !== clientOrigin(req)) return bad(res, "fpBad");
    if (![-7, -257].includes(Number(b.alg)) || !b.rawId || !b.publicKey) return bad(res, "fpBad");
    crypto.createPublicKey({ key: b64u.dec(b.publicKey), format: "der", type: "spki" });
    const rpId = rpHostOf(req);
    db.credentials = db.credentials.filter((c) => c.credentialId !== b.rawId);
    db.credentials.push({ userId: t.userId, credentialId: b.rawId, publicKey: b.publicKey, alg: Number(b.alg), rpId, createdAt: new Date().toISOString() });
    save();
    t.status = "done";
    res.json({ ok: true });
  } catch (err) { bad(res, "fpBad"); }
});

app.post("/api/fp/ticket/:id/assert", (req, res) => {
  const t = getTicket(req.params.id);
  if (!t || t.purpose !== "login") return bad(res, "expired", 404);
  if (t.status !== "pending") return bad(res, "used", 409);
  try {
    const b = req.body || {};
    const allowed = t.credentialIds || (t.credentialId ? [t.credentialId] : []);
    const cred = db.credentials.find((c) => c.userId === t.userId && c.credentialId === b.credentialId && allowed.includes(b.credentialId));
    if (!cred) return bad(res, "fpBad");
    const cdRaw = b64u.dec(b.clientDataJSON);
    const cd = JSON.parse(cdRaw.toString("utf8"));
    if (cd.type !== "webauthn.get" || cd.challenge !== t.challenge || cd.origin !== clientOrigin(req)) return bad(res, "fpBad");
    const authData = b64u.dec(b.authenticatorData);
    if (!authData.subarray(0, 32).equals(sha256(Buffer.from(rpHostOf(req))))) return bad(res, "fpBad");
    const flags = authData[32];
    if (!(flags & 1) || !(flags & 4)) return bad(res, "fpBad");
    const signed = Buffer.concat([authData, sha256(cdRaw)]);
    const key = crypto.createPublicKey({ key: b64u.dec(cred.publicKey), format: "der", type: "spki" });
    if (!crypto.verify("sha256", signed, { key, dsaEncoding: "der" }, b64u.dec(b.signature))) return bad(res, "fpBad");

    const user = db.users.find((u) => u.nhrId === t.userId);
    t.status = "approved";
    if (t.doctorToken) return res.json({ ok: true });
    reactivate(user);
    t.token = makeSession({ type: "nid", name: user.fullName, nhrId: user.nhrId });
    t.user = { type: "nid", name: user.fullName, nhrId:user.nhrId,uid:user.uid||"",email:user.email||"",nid:user.nid||""};
    res.json({ ok: true });
  } catch (err) { bad(res, "fpBad"); }
});

app.get("/api/fp/ticket/:id/status", (req, res) => {
  const t = getTicket(req.params.id);
  if (!t) return res.json({ status: "expired" });
  if (t.pollKey !== req.query.k) return bad(res, "serverErr", 403);
  if (t.status === "approved") { tickets.delete(t.id); return res.json({ status: "approved", token: t.token, user: t.user }); }
  if (t.status === "done") { tickets.delete(t.id); return res.json({ status: "done" }); }
  res.json({ status: "pending" });
});

/* ---------- Patient Data ---------- */
const tokenOf = (req) => s(req.get("authorization")).replace(/^Bearer\s+/i, "");

app.get("/api/patient/profile", (req, res) => {
  const ses = getSes(req);
  if (!ses || !["nid", "brn"].includes(ses.type)) return bad(res, "noSession", 401);
  const u = db.users.find((x) => x.nhrId === ses.nhrId);
  if (!u) return bad(res, "noUser", 404);
  const { passwordHash, doctor, ...safe } = u;
  safe.hasFingerprint = db.credentials.some((c) => c.userId === u.nhrId);
  safe.alsoDoctor = !!doctor;
  res.json({ ok: true, profile: safe });
});

app.post("/api/logout", (req, res) => {
  sessions.delete(tokenOf(req));
  res.json({ ok: true });
});

/* ---------- Session Expiry ---------- */
const SESSION_MS = 12 * 3600 * 1000;
function getSes(req) {
  const tok = tokenOf(req), x = sessions.get(tok);
  if (!x) return null;
  if (Date.now() - x.at > SESSION_MS) { sessions.delete(tok); return null; }
  return Object.assign({ token: tok }, x);
}
const patientSes = (req) => { const x = getSes(req); return x && x.type === "nid" ? x : null; };
const patientUser = (x) => db.users.find((u) => u.nhrId === x.nhrId);
function endSessions(x, keepToken) { for (const [k, v] of sessions) if (v.nhrId === x.nhrId && v.type === x.type && k !== keepToken) sessions.delete(k); }
function reactivate(u) { if (u.status && u.status !== "active") { u.status = "active"; delete u.deleteAfter; save(); } }

function gate(key, ok) {
  const m = lockMin(key); if (m) return { error: "locked", m, code: 429 };
  if (ok()) { fails.delete(key); return null; }
  const left = addFail(key);
  return left ? { error: "wrongPw", left, code: 401 } : { error: "locked", m: 5, code: 429 };
}
const gateErr = (res, r) => bad(res, r.error === "wrongPw" ? "wrongPw" : r.error, r.code, r);

/* ---------- Patient Settings & History ---------- */
app.post("/api/account/deactivate", (req, res) => {
  const x = patientSes(req); if (!x) return bad(res, "noSession", 401);
  const u = patientUser(x), b = req.body || {};
  const r = gate("acct:" + x.nhrId, () => u && checkPw(String(b.password || ""), u.passwordHash));
  if (r) return gateErr(res, r);
  u.status = "deactivated"; u.deactivatedAt = new Date().toISOString(); u.deactivateReason = s(b.reason).slice(0, 80);
  save(); endSessions(x); res.json({ ok: true });
});

app.post("/api/account/delete", (req, res) => {
  const x = patientSes(req); if (!x) return bad(res, "noSession", 401);
  const u = patientUser(x);
  const r = gate("acct:" + x.nhrId, () => u && checkPw(String((req.body && req.body.password) || ""), u.passwordHash));
  if (r) return gateErr(res, r);
  u.status = "pending_delete"; u.deleteAfter = new Date(Date.now() + 30 * 86400000).toISOString();
  save(); endSessions(x); res.json({ ok: true, deleteAfter: u.deleteAfter });
});

app.post("/api/account/password", (req, res) => {
  const x = patientSes(req); if (!x) return bad(res, "noSession", 401);
  const u = patientUser(x), b = req.body || {}, next = String(b.next || "");
  if (next.length < 8) return bad(res, "ePwLen");
  const r = gate("acct:" + x.nhrId, () => u && checkPw(String(b.current || ""), u.passwordHash));
  if (r) return gateErr(res, r);
  u.passwordHash = hashPw(next); save(); endSessions(x, x.token); res.json({ ok: true });
});

app.post("/api/logout-all", (req, res) => {
  const x = getSes(req); if (!x) return bad(res, "noSession", 401);
  endSessions(x); res.json({ ok: true });
});

app.post("/api/patient/prefs", (req, res) => {
  const x = patientSes(req); if (!x) return bad(res, "noSession", 401);
  const b = req.body || {}; patientUser(x).prefs = { em: b.em !== false, notif: b.notif !== false }; save(); res.json({ ok: true });
});

app.post("/api/patient/emergency", (req, res) => {
  const x = getSes(req); if (!x || !["nid", "brn"].includes(x.type)) return bad(res, "noSession", 401);
  const u = patientUser(x), b = req.body || {};
  if (!u || s(b.name).length < 2 || !/^01[3-9]\d{8}$/.test(s(b.phone))) return bad(res, "emNeed");
  u.emergency = { name: s(b.name).slice(0, 60), relation: s(b.relation).slice(0, 30), phone: s(b.phone) };
  save(); res.json({ ok: true });
});

const METHOD_TXT = {
  fp: { en: "Opened your record (fingerprint)", bn: "আপনার রেকর্ড খুলেছেন (ফিঙ্গারপ্রিন্ট)" },
  otp: { en: "Opened your record (phone OTP)", bn: "আপনার রেকর্ড খুলেছেন (ফোন ওটিপি)" },
  em: { en: "Emergency access to your Emergency Card", bn: "আপনার জরুরি কার্ডে জরুরি অ্যাক্সেস" }
};

app.get("/api/patient/records", (req, res) => {
  const x = getSes(req); if (!x || !["nid", "brn"].includes(x.type)) return bad(res, "noSession", 401);
  const u = patientUser(x); if (!u) return bad(res, "noUser", 404);
  res.json({
    ok: true,
    records: db.records.filter((r) => r.nhrId === u.nhrId).sort((a, b) => b.at - a.at).map((r) => ({ date: r.date, type: r.type, title: r.title, by: r.by, detail: r.detail })),
    allergies: u.allergies || [], conditions: u.conditions || [],
    audit: db.audit.filter((a) => a.patientId === u.nhrId).sort((a, b) => b.at - a.at).slice(0, 20).map((a) => ({ who: a.doctorName, what: a.scope === "upload" ? { en: "Was allowed to add a report to your record", bn: "আপনার রেকর্ডে রিপোর্ট যোগ করার অনুমতি পেয়েছে" } : (METHOD_TXT[a.method] || METHOD_TXT.otp), when: new Date(a.at).toISOString() }))
  });
});

/* ---------- Direct Biometric Challenge ---------- */
const directChallenges = new Map();
app.post("/api/fp/direct-challenge", (req, res) => {
  const x = patientSes(req); if (!x) return bad(res, "noSession", 401);
  const challenge = b64u.enc(rand(32)); directChallenges.set(x.token, { challenge, exp: Date.now() + 5 * 60000 });
  res.json({ ok: true, challenge });
});

app.post("/api/fp/direct-enroll", (req, res) => {
  const x = patientSes(req); if (!x) return bad(res, "noSession", 401);
  const c = directChallenges.get(x.token); directChallenges.delete(x.token);
  if (!c || c.exp < Date.now()) return bad(res, "fpBad");
  try {
    const b = req.body || {}, cd = JSON.parse(b64u.dec(b.clientDataJSON).toString("utf8"));
    if (cd.type !== "webauthn.create" || cd.challenge !== c.challenge || cd.origin !== originOf(req)) return bad(res, "fpBad");
    if (![-7, -257].includes(Number(b.alg)) || !b.rawId || !b.publicKey) return bad(res, "fpBad");
    crypto.createPublicKey({ key: b64u.dec(b.publicKey), format: "der", type: "spki" });
    const rpId = rpHostOf(req);
    db.credentials = db.credentials.filter((k) => !(k.userId === x.nhrId && k.rpId === rpId));
    db.credentials.push({ userId: x.nhrId, credentialId: b.rawId, publicKey: b.publicKey, alg: Number(b.alg), rpId, createdAt: new Date().toISOString() });
    save(); res.json({ ok: true });
  } catch (err) { bad(res, "fpBad"); }
});

/* ================= Doctor Portal ================= */
const grants = new Map();
const otps = new Map();

function docSes(req) {
  const x = getSes(req); if (!x || x.type !== "doctor") return null;
  const u = db.users.find((v) => v.nhrId === x.nhrId);
  return u && u.doctor && u.doctor.status === "verified" ? Object.assign(x, { u }) : null;
}

const patientOf = (id) => db.users.find((v) => (v.nhrId === s(id).toUpperCase() || v.brn === s(id).toUpperCase()) && v.patientActive !== false && (!v.status || v.status === "active"));
const maskName = (n) => s(n).split(/\s+/).map((w) => w[0] + "•".repeat(Math.min(Math.max(w.length - 1, 1), 5))).join(" ");

function grantFor(doc, p, scope, via, mins, extra) {
  const token = rand(24).toString("hex"), exp = Date.now() + mins * 60000;
  grants.set(token, { doctorId: doc.nhrId, patientId: p.nhrId, scope, exp, via });
  db.audit.push(Object.assign({ id: rand(8).toString("hex"), doctorId: doc.nhrId, doctorName: doc.fullName, patientId: p.nhrId, method: via, scope, at: Date.now() }, extra || {}));
  save();
  return { ok: true, scope, token, expiresAt: exp };
}

function grantOf(req, d, patientId, needFull) {
  const g = grants.get(s(req.get("x-access-token")));
  if (!g || g.doctorId !== d.nhrId || g.patientId !== patientId || g.exp < Date.now()) return null;
  return needFull && g.scope !== "full" ? null : g;
}

app.get("/api/doctor/profile", (req, res) => {
  const d = docSes(req); if (!d) return bad(res, "noSession", 401);
  const u = d.u;
  res.json({ ok: true, profile: { name: /^dr\.?\s/i.test(u.fullName) ? u.fullName : "Dr. " + u.fullName, bmdc: u.doctor.license, specialty: u.doctor.speciality, hospital: u.doctor.hospital } });
});

app.post("/api/doctor/search", (req, res) => {
  const d = docSes(req); if (!d) return bad(res, "noSession", 401);
  const rawKey = s(req.body && req.body.nhrId).toUpperCase();
  const key = rawKey.replace(/\D/g, "");
  const p = db.users.find((v) => (v.nhrId === key || v.nid === key || v.brn === rawKey) && v.patientActive !== false && (!v.status || v.status === "active"));
  if (!p) return bad(res, "nf", 404);
  res.json({ ok: true, patient: { nhrId: p.nhrId, maskedName: maskName(p.fullName), age: ageOf(p.dob), gender: p.gender[0], phoneEnd: p.phone.slice(-2), bloodGroup: p.bloodGroup, emergency: p.emergency } });
});

function resolveDocCtx(req) {
  const sesDoc = docSes(req);
  if (sesDoc) return sesDoc;
  const fbd = req.body && req.body.fbDoctor;
  if (fbd && (fbd.uid || fbd.bmdc)) {
    const docId = s(fbd.bmdc || fbd.uid);
    return {
      token: "fb_" + s(fbd.uid || fbd.bmdc),
      u: {
        nhrId: docId,
        fullName: s(fbd.name || "Doctor"),
        doctor: {
          license: s(fbd.bmdc || "DOC"),
          hospital: s(fbd.hospital || "Hospital"),
          speciality: s(fbd.specialty || "General Medicine")
        }
      }
    };
  }
  return null;
}

function resolvePatientCtx(req) {
  const fbp = req.body && req.body.fbPatient;
  if (fbp) {
    const u = ensureFb(fbp);
    if (u) {
      if (fbp.phone) u.phone = s(fbp.phone);
      if (fbp.prefs) u.prefs = fbp.prefs;
      save();
      return u;
    }
  }
  return patientOf(req.body && req.body.nhrId);
}

app.post("/api/doctor/verify/fp-start", (req, res) => {
  const d = resolveDocCtx(req); if (!d) return bad(res, "noSession", 401);
  const p = resolvePatientCtx(req); if (!p) return bad(res, "nf", 404);
  const creds = db.credentials.filter((c) => c.userId === p.nhrId);
  if (!creds.length) return bad(res, "fpNone", 404);
  const hostCreds = creds.filter((c) => c.rpId === rpHostOf(req));
  if (!hostCreds.length) return bad(res, "fpOtherHost", 409);
  const t = newTicket({ purpose: "login", userId: p.nhrId, name: p.fullName, credentialId: hostCreds[0].credentialId, credentialIds: hostCreds.map(c => c.credentialId), pollKey: rand(16).toString("hex"), lang: "en", doctorToken: d.token, fbDoc: d.u });
  res.json({ ok: true, requestId: t.id, qrUrl: baseOf(req) + "/m.html?t=" + t.id });
});

app.get("/api/doctor/verify/fp-status", (req, res) => {
  const d = docSes(req) || (req.query.dt ? { token: "fb_" + s(req.query.dt), u: null } : null);
  if (!d) return bad(res, "noSession", 401);
  const t = getTicket(s(req.query.id));
  if (!t || t.doctorToken !== d.token) return res.json({ status: "denied" });
  if (t.status !== "approved") return res.json({ status: "pending" });
  tickets.delete(t.id);
  const p = patientOf(t.userId); if (!p) return res.json({ status: "denied" });
  const docUser = d.u || t.fbDoc || { nhrId: "DOC", fullName: "Doctor" };
  res.json(Object.assign({ status: "approved" }, grantFor(docUser, p, "full", "fp", 15)));
});

// Doctor OTP Verification with Real Gmail Delivery
app.post("/api/doctor/verify/otp-send", async (req, res) => {
  const d = resolveDocCtx(req); if (!d) return bad(res, "noSession", 401);
  const p = resolvePatientCtx(req); if (!p) return bad(res, "nf", 404);
  if (!p.email) return bad(res, "noEmail", 400);
  const key = d.token + "|" + p.nhrId, o = otps.get(key);
  if (o && Date.now() - o.sentAt < 30000) return bad(res, "wait", 429);
  const code = String(crypto.randomInt(100000, 1000000));
  otps.set(key, { code, exp: Date.now() + 5 * 60000, tries: 0, sentAt: Date.now() });
  console.log("[OTP Code] to " + p.email + ": " + code);

  const sent = await sendOtpEmail(p.email, p.fullName, code);
  if (!sent) { otps.delete(key); return bad(res, "mailFail", 500); }
  res.json({ ok: true });
});

app.post("/api/doctor/verify/otp-verify", (req, res) => {
  const d = resolveDocCtx(req); if (!d) return bad(res, "noSession", 401);
  const p = resolvePatientCtx(req); if (!p) return bad(res, "nf", 404);
  const key = d.token + "|" + p.nhrId, o = otps.get(key), code = s(req.body && req.body.code);
  if (!o || o.exp < Date.now()) return bad(res, "badOtp", 400);
  if (++o.tries > 5) { otps.delete(key); return bad(res, "badOtp", 429); }
  if (code.length !== o.code.length || !crypto.timingSafeEqual(Buffer.from(code), Buffer.from(o.code))) return bad(res, "badOtp", 400);
  otps.delete(key);
  res.json(grantFor(d.u, p, "full", "otp", 15));
});

// Doctor Emergency Access with Real Gmail Alert
app.post("/api/doctor/verify/emergency", async (req, res) => {
  const d = resolveDocCtx(req); if (!d) return bad(res, "noSession", 401);
  const p = resolvePatientCtx(req); if (!p) return bad(res, "nf", 404);
  const reason = s(req.body && req.body.reason), note = s(req.body && req.body.note);
  if (!["unconscious", "lifethreat", "noconsent", "other"].includes(reason) || note.length < 15) return bad(res, "emShort");
  if (p.prefs && p.prefs.em === false) return bad(res, "emOff", 403);

  const timeNow = new Date().toLocaleString("en-US", { timeZone: "Asia/Dhaka" });
  console.log(`[EMERGENCY OVERRIDE] Doctor ${d.u.doctor.license} opened patient ${p.nhrId} at ${timeNow}`);
  if (p.email) {
    const sent = await sendEmergencyAlertEmail(p.email, p.fullName, d.u.fullName, d.u.doctor.hospital, note, timeNow);
    if (!sent) return bad(res, "mailFail", 500);
  }

  res.json(grantFor(d.u, p, "emergency", "em", 30, { reason, note: note.slice(0, 500) }));
});

app.post("/api/doctor/patient", (req, res) => {
  const d = docSes(req); if (!d) return bad(res, "noSession", 401);
  const id = s(req.body && req.body.nhrId), g = grantOf(req, d, id, false);
  if (!g) return bad(res, "noAccess", 403);
  const p = patientOf(id); if (!p) return bad(res, "nf", 404);
  const full = g.scope === "full";
  res.json({
    ok: true,
    patient: { nhrId: p.nhrId, fullName: p.fullName, age: ageOf(p.dob), gender: p.gender, bloodGroup: p.bloodGroup, emergency: p.emergency },
    allergies: p.allergies || [], conditions: p.conditions || [], meds: p.meds || [],
    records: full ? db.records.filter((r) => r.nhrId === p.nhrId).sort((a, b) => b.at - a.at).map((r) => ({ date: r.date, type: r.type, title: r.title, by: r.by, detail: r.detail })) : []
  });
});

app.post("/api/doctor/records", (req, res) => {
  const d = docSes(req); if (!d) return bad(res, "noSession", 401);
  const b = req.body || {}, id = s(b.nhrId);
  if (!grantOf(req, d, id, true)) return bad(res, "noAccess", 403);
  const type = s(b.type), title = s(b.title), detail = s(b.detail);
  if (!["rx", "lab", "vac", "visit"].includes(type) || title.length < 2 || title.length > 120 || detail.length < 2 || detail.length > 3000) return bad(res, "serverErr");
  db.records.push({ id: rand(8).toString("hex"), nhrId: id, type, title, detail, by: d.u.fullName + " · " + d.u.doctor.speciality, doctorId: d.nhrId, date: new Date().toISOString().slice(0, 10), at: Date.now() });
  save(); res.json({ ok: true });
});

app.get("/api/doctor/audit", (req, res) => {
  const d = docSes(req); if (!d) return bad(res, "noSession", 401);
  res.json({ ok: true, log: db.audit.filter((a) => a.doctorId === d.nhrId).sort((a, b) => b.at - a.at).slice(0, 50).map((a) => { const p = db.users.find((u) => u.nhrId === a.patientId); return { when: a.at, nhrId: a.patientId, name: p ? p.fullName : "–", method: a.method }; }) });
});

/* ================= Hospital / Lab Portal ================= */
const findPatient = (raw) => {
  const key = s(raw).toUpperCase();
  const digitsOnly = key.replace(/\D/g, "");
  return db.users.find((v) => (v.nhrId === digitsOnly || v.nid === digitsOnly || v.brn === key) && v.patientActive !== false && (!v.status || v.status === "active"));
};

function facSes(req) {
  const x = getSes(req); if (!x || x.type !== "facility") return null;
  const f = db.facilities.find((v) => v.id === x.nhrId);
  return f && f.status === "active" ? Object.assign(x, { f }) : null;
}

function grantUpload(f, p, via) {
  const token = rand(24).toString("hex"), exp = Date.now() + 20 * 60000;
  grants.set(token, { doctorId: f.id, patientId: p.nhrId, scope: "upload", exp, via });
  db.audit.push({ id: rand(8).toString("hex"), actor: "facility", doctorId: f.id, doctorName: f.name, patientId: p.nhrId, method: via, scope: "upload", at: Date.now() });
  save();
  return { ok: true, scope: "upload", token, expiresAt: exp };
}

// Hospital Registration for Newborns (B + 8 Digits Temp Birth ID)
app.post("/api/facility/birth-register", (req, res) => {
  const x = facSes(req); if (!x) return bad(res, "noSession", 401);
  const b = req.body || {};
  const birthId = s(b.birthId).toUpperCase();
  if (!/^B\d{8}$/.test(birthId)) return bad(res, "invalidBirthId");
  if (db.users.some((u) => u.nhrId === birthId || u.brn === birthId)) return bad(res, "dupBirthId", 409);
  const dob = s(b.dob);
  if (dob && (isNaN(new Date(dob)) || new Date(dob) > new Date())) return bad(res, "eDob");

  const babyUser = {
    nhrId: birthId,
    brn: birthId,
    fullName: s(b.babyName) || "Newborn Baby",
    dob: dob || new Date().toISOString().slice(0, 10),
    gender: s(b.gender) || "Male",
    phone: s(b.phone),
    bloodGroup: s(b.bloodGroup) || "Unknown",
    motherNhr: s(b.motherNhr),
    weight: s(b.weight),
    patientActive: true,
    status: "active",
    createdAt: new Date().toISOString()
  };

  db.users.push(babyUser);
  save();
  res.json({ ok: true, birthId, user: babyUser });
});

// Update Facility Profile
app.post("/api/facility/update-profile", (req, res) => {
  const x = facSes(req); if (!x) return bad(res, "noSession", 401);
  const b = req.body || {};
  Object.assign(x.f, {
    phone: s(b.phone) || x.f.phone,
    schedule: s(b.schedule) || x.f.schedule || "24/7 Open",
    district: s(b.district) || x.f.district,
    address: s(b.address) || x.f.address,
    services: Array.isArray(b.services) ? b.services : x.f.services || []
  });
  save();
  res.json({ ok: true, profile: x.f });
});

app.get("/api/facility/profile", (req, res) => {
  const x = facSes(req); if (!x) return bad(res, "noSession", 401);
  const f = x.f;
  res.json({ ok: true, profile: { id: f.id, name: f.name, type: f.type, license: f.license, district: f.district, address: f.address, contactPerson: f.contactPerson, phone: f.phone, schedule: f.schedule || "24/7 Open", services: f.services || [], tempPw: !!f.tempPw } });
});

app.post("/api/facility/search", (req, res) => {
  const x = facSes(req); if (!x) return bad(res, "noSession", 401);
  const p = findPatient(req.body && req.body.nhrId); if (!p) return bad(res, "nf", 404);
  res.json({ ok: true, patient: { nhrId: p.nhrId, maskedName: maskName(p.fullName), age: ageOf(p.dob), gender: p.gender[0], phoneEnd: p.phone.slice(-2) } });
});

app.post("/api/facility/verify/otp-send", async (req, res) => {
  const x = facSes(req); if (!x) return bad(res, "noSession", 401);
  const p = findPatient(req.body && req.body.nhrId); if (!p) return bad(res, "nf", 404);
  const key = x.token + "|" + p.nhrId, o = otps.get(key);
  if (o && Date.now() - o.sentAt < 30000) return bad(res, "wait", 429);
  const code = String(crypto.randomInt(100000, 1000000));
  otps.set(key, { code, exp: Date.now() + 5 * 60000, tries: 0, sentAt: Date.now() });
  console.log("[Facility OTP] to " + p.phone + ": " + code);

  if (p.email) sendOtpEmail(p.email, p.fullName, code);
  res.json({ ok: true });
});

app.post("/api/facility/verify/otp-verify", (req, res) => {
  const x = facSes(req); if (!x) return bad(res, "noSession", 401);
  const p = findPatient(req.body && req.body.nhrId); if (!p) return bad(res, "nf", 404);
  const key = x.token + "|" + p.nhrId, o = otps.get(key), code = s(req.body && req.body.code);
  if (!o || o.exp < Date.now()) return bad(res, "badOtp", 400);
  if (++o.tries > 5) { otps.delete(key); return bad(res, "badOtp", 429); }
  if (code.length !== o.code.length || !crypto.timingSafeEqual(Buffer.from(code), Buffer.from(o.code))) return bad(res, "badOtp", 400);
  otps.delete(key);
  res.json(grantUpload(x.f, p, "otp"));
});

app.post("/api/facility/verify/fp-start", (req, res) => {
  const x = facSes(req); if (!x) return bad(res, "noSession", 401);
  const p = findPatient(req.body && req.body.nhrId); if (!p) return bad(res, "nf", 404);
  const creds = db.credentials.filter((c) => c.userId === p.nhrId);
  if (!creds.length) return bad(res, "fpNone", 404);
  const cred = creds.find((c) => c.rpId === rpHostOf(req)); if (!cred) return bad(res, "fpOtherHost", 409);
  const t = newTicket({ purpose: "login", userId: p.nhrId, name: p.fullName, credentialId: cred.credentialId, pollKey: rand(16).toString("hex"), lang: "en", doctorToken: x.token });
  res.json({ ok: true, requestId: t.id, qrUrl: baseOf(req) + "/m.html?t=" + t.id });
});

app.get("/api/facility/verify/fp-status", (req, res) => {
  const x = facSes(req); if (!x) return bad(res, "noSession", 401);
  const t = getTicket(s(req.query.id));
  if (!t || t.doctorToken !== x.token) return res.json({ status: "denied" });
  if (t.status !== "approved") return res.json({ status: "pending" });
  tickets.delete(t.id);
  const p = db.users.find((u) => u.nhrId === t.userId); if (!p) return res.json({ status: "denied" });
  res.json(Object.assign({ status: "approved" }, grantUpload(x.f, p, "fp")));
});

app.post("/api/facility/reports", (req, res) => {
  const x = facSes(req); if (!x) return bad(res, "noSession", 401);
  const b = req.body || {}, id = s(b.nhrId), g = grants.get(s(req.get("x-access-token")));
  if (!g || g.doctorId !== x.f.id || g.patientId !== id || g.scope !== "upload" || g.exp < Date.now()) return bad(res, "noAccess", 403);
  const p = db.users.find((u) => u.nhrId === id); if (!p) return bad(res, "nf", 404);
  const title = s(b.title), notes = s(b.notes).slice(0, 1000), reportNo = s(b.reportNo).slice(0, 40), date = s(b.date);
  const category = ["blood", "urine", "imaging", "other"].includes(s(b.category)) ? s(b.category) : "other";
  const items = (Array.isArray(b.items) ? b.items : []).slice(0, 40).map((i) => ({ name: s(i.name).slice(0, 60), value: s(i.value).slice(0, 40), unit: s(i.unit).slice(0, 20), range: s(i.range).slice(0, 40), flag: ["normal", "high", "low", "critical"].includes(s(i.flag)) ? s(i.flag) : "normal" })).filter((i) => i.name && i.value);
  if (title.length < 2 || title.length > 120 || (!items.length && notes.length < 2)) return bad(res, "serverErr");
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date) || isNaN(new Date(date)) || new Date(date) > new Date(Date.now() + 86400000) || date < "2000-01-01") return bad(res, "eDate");
  const detail = (items.map((i) => i.name + ": " + i.value + (i.unit ? " " + i.unit : "") + (i.range ? " (ref " + i.range + ")" : "") + (i.flag !== "normal" ? " [" + i.flag.toUpperCase() + "]" : "")).join("; ") + (notes ? (items.length ? ". " : "") + notes : "")).slice(0, 3000);
  db.records.push({ id: rand(8).toString("hex"), nhrId: id, type: "lab", title, detail, by: x.f.name, facilityId: x.f.id, category, reportNo, items, notes, date, at: Date.now() });
  save();
  res.json({ ok: true, critical: items.some((i) => i.flag === "critical") });
});

app.get("/api/facility/reports", (req, res) => {
  const x = facSes(req); if (!x) return bad(res, "noSession", 401);
  res.json({ ok: true, reports: db.records.filter((r) => r.facilityId === x.f.id).sort((a, b) => b.at - a.at).slice(0, 100).map((r) => { const p = db.users.find((u) => u.nhrId === r.nhrId); return { when: r.at, date: r.date, nhrId: r.nhrId, patient: p ? maskName(p.fullName) : "–", title: r.title, reportNo: r.reportNo || "", category: r.category, critical: (r.items || []).some((i) => i.flag === "critical") }; }) });
});

app.post("/api/facility/password", (req, res) => {
  const x = facSes(req); if (!x) return bad(res, "noSession", 401);
  const b = req.body || {}, next = String(b.next || "");
  if (next.length < 8) return bad(res, "ePwLen");
  const r = gate("fac:" + x.f.id, () => checkPw(String(b.current || ""), x.f.passwordHash));
  if (r) return gateErr(res, r);
  x.f.passwordHash = hashPw(next); delete x.f.tempPw; save(); endSessions(x, x.token); res.json({ ok: true });
});

/* ---------- Admin Management ---------- */
function tempPassword() {
  const L = "ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz", D = "23456789", pick = (set, n) => Array.from({ length: n }, () => set[crypto.randomInt(set.length)]);
  const a = pick(L, 7).concat(pick(D, 3)); for (let i = a.length - 1; i > 0; i--) { const j = crypto.randomInt(i + 1); [a[i], a[j]] = [a[j], a[i]]; }
  return a.join("");
}

const adminSes = (req) => { const x = getSes(req); return x && x.type === "admin" ? x : null; };
const maskNid = (n) => s(n).slice(0, 4) + "••••••••" + s(n).slice(-4);

app.get("/api/admin/stats", (req, res) => {
  if (!adminSes(req)) return bad(res, "noSession", 401);
  const day = new Date(); day.setHours(0, 0, 0, 0);
  const docs = db.users.filter((u) => u.doctor), em = db.audit.filter((a) => a.method === "em");
  res.json({ ok: true, stats: {
    patients: db.users.filter((u) => u.patientActive !== false).length,
    doctors: docs.length, pending: docs.filter((u) => u.doctor.status === "pending").length,
    verified: docs.filter((u) => u.doctor.status === "verified").length,
    blocked: docs.filter((u) => ["rejected", "suspended"].includes(u.doctor.status)).length,
    accessToday: db.audit.filter((a) => a.at >= day.getTime()).length,
    emergencyToday: em.filter((a) => a.at >= day.getTime()).length, emergencyTotal: em.length, records: db.records.length, facilities: db.facilities.length, labReports: db.records.filter((r) => r.facilityId).length
  } });
});

app.get("/api/admin/doctors", (req, res) => {
  if (!adminSes(req)) return bad(res, "noSession", 401);
  res.json({ ok: true, doctors: db.users.filter((u) => u.doctor).sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt))).map((u) => ({
    license: u.doctor.license, name: u.fullName, speciality: u.doctor.speciality, hospital: u.doctor.hospital, status: u.doctor.status,
    nid: maskNid(u.nid), phone: u.phone, registeredAt: u.createdAt, reviewedAt: u.doctor.reviewedAt || null, reviewNote: u.doctor.reviewNote || ""
  })) });
});

app.post("/api/admin/doctors/verify", (req, res) => {
  const x = adminSes(req); if (!x) return bad(res, "noSession", 401);
  const b = req.body || {}, st = { verify: "verified", reject: "rejected", suspend: "suspended" }[s(b.action)];
  const u = db.users.find((v) => v.doctor && v.doctor.license === s(b.license));
  if (!u) return bad(res, "noUser", 404);
  if (!st) return bad(res, "serverErr");
  Object.assign(u.doctor, { status: st, reviewedBy: x.nhrId, reviewedAt: new Date().toISOString(), reviewNote: s(b.note).slice(0, 200) });
  if (st !== "verified") {
    for (const [k, v] of sessions) if (v.type === "doctor" && v.nhrId === u.nhrId) sessions.delete(k);
    for (const [k, g] of grants) if (g.doctorId === u.nhrId) grants.delete(k);
  }
  save(); res.json({ ok: true, status: st });
});

app.get("/api/admin/audit", (req, res) => {
  if (!adminSes(req)) return bad(res, "noSession", 401);
  const onlyEm = req.query.type === "em";
  res.json({ ok: true, log: db.audit.filter((a) => !onlyEm || a.method === "em").sort((a, b) => b.at - a.at).slice(0, 100).map((a) => {
    const d = db.users.find((u) => u.nhrId === a.doctorId), p = db.users.find((u) => u.nhrId === a.patientId);
    return { when: a.at, doctorName: a.doctorName, license: d && d.doctor ? d.doctor.license : (a.actor === "facility" ? a.doctorId : "–"), patientId: a.patientId, patient: p ? maskName(p.fullName) : "–", method: a.method, scope: a.scope, reason: a.reason || "", note: a.note || "" };
  }) });
});

app.get("/api/admin/patients", (req, res) => {
  if (!adminSes(req)) return bad(res, "noSession", 401);
  res.json({ ok: true, patients: db.users.filter((u) => u.patientActive !== false).sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt))).map((u) => ({
    nhrId: u.nhrId, maskedName: maskName(u.fullName), district: u.district, registeredAt: u.createdAt, status: u.status || "active",
    fingerprint: db.credentials.some((c) => c.userId === u.nhrId), alsoDoctor: !!u.doctor
  })) });
});

const facOut = (f) => ({ id: f.id, name: f.name, type: f.type, license: f.license, district: f.district, address: f.address, contactPerson: f.contactPerson, phone: f.phone, schedule: f.schedule || "24/7 Open", services: f.services || [], status: f.status, createdAt: f.createdAt, reports: db.records.filter((r) => r.facilityId === f.id).length });

app.get("/api/admin/facilities", (req, res) => {
  if (!adminSes(req)) return bad(res, "noSession", 401);
  res.json({ ok: true, facilities: db.facilities.slice().sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt))).map(facOut) });
});

app.post("/api/admin/facilities", (req, res) => {
  const x = adminSes(req); if (!x) return bad(res, "noSession", 401);
  const b = req.body || {}, name = s(b.name), license = s(b.license);
  if (name.length < 3 || !["hospital", "clinic", "lab"].includes(s(b.type)) || license.length < 3 || s(b.district).length < 2 || s(b.address).length < 5 || s(b.contactPerson).length < 3 || !/^\d{7,15}$/.test(s(b.phone))) return bad(res, "serverErr");
  if (db.facilities.some((f) => f.license.toLowerCase() === license.toLowerCase())) return bad(res, "dupLic", 409);
  let id; do { id = "FAC" + crypto.randomInt(10000000, 100000000); } while (db.facilities.some((f) => f.id === id));
  const password = tempPassword();
  const f = { id, name, type: s(b.type), license, district: s(b.district), address: s(b.address), contactPerson: s(b.contactPerson), phone: s(b.phone), schedule: "24/7 Open", services: [], status: "active", passwordHash: hashPw(password), tempPw: true, createdBy: x.nhrId, createdAt: new Date().toISOString() };
  db.facilities.push(f); save();
  res.json({ ok: true, id, password, facility: facOut(f) });
});

app.post("/api/admin/facilities/status", (req, res) => {
  if (!adminSes(req)) return bad(res, "noSession", 401);
  const b = req.body || {}, f = db.facilities.find((v) => v.id === s(b.id)); if (!f) return bad(res, "noUser", 404);
  const act = s(b.action); let password;
  if (act === "suspend") f.status = "suspended";
  else if (act === "activate") f.status = "active";
  else if (act === "reset") { password = tempPassword(); f.passwordHash = hashPw(password); f.tempPw = true; }
  else return bad(res, "serverErr");
  if (act !== "activate") {
    for (const [k, v] of sessions) if (v.type === "facility" && v.nhrId === f.id) sessions.delete(k);
    for (const [k, g] of grants) if (g.doctorId === f.id) grants.delete(k);
  }
  save(); res.json({ ok: true, status: f.status, password });
});

/* ================= Blood Donors, Requests, Hospital Blood Stock, Notifications ================= */
const GROUPS = ["A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-"];
const CAN_RECEIVE = {
  "A+": ["A+", "A-", "O+", "O-"], "A-": ["A-", "O-"], "B+": ["B+", "B-", "O+", "O-"], "B-": ["B-", "O-"],
  "AB+": GROUPS, "AB-": ["A-", "B-", "AB-", "O-"], "O+": ["O+", "O-"], "O-": ["O-"]
};
const GAP_DAYS = 90;
const isActive = (u) => u.patientActive !== false && (!u.status || u.status === "active");
const cap = (v) => String(v).charAt(0).toUpperCase() + String(v).slice(1);

function auth(req, res, types) {
  const x = getSes(req);
  if (!x || (types && !types.includes(x.type))) { bad(res, "noSession", 401); return null; }
  return x;
}
const userOf = (x) => db.users.find((u) => u.nhrId === x.nhrId);
const refOf = (id) => crypto.createHmac("sha256", db.secret).update("donor:" + id).digest("hex").slice(0, 16);
const hits = new Map();
function limited(key, max, ms) {
  const now = Date.now(), arr = (hits.get(key) || []).filter((t) => now - t < ms);
  if (arr.length >= max) { hits.set(key, arr); return true; }
  arr.push(now); hits.set(key, arr); return false;
}
function notify(userId, n) {
  const list = (db.notifs[userId] = db.notifs[userId] || []);
  list.unshift(Object.assign({ id: rand(6).toString("hex"), at: new Date().toISOString(), read: false }, n));
  if (list.length > 50) list.length = 50;
}
const daysSince = (d) => Math.floor((Date.now() - new Date(d).getTime()) / 86400000);
const eligibleNow = (d) => d.available !== false && (!d.lastDonation || daysSince(d.lastDonation) >= GAP_DAYS);
const nextDate = (d) => (d.lastDonation ? new Date(new Date(d.lastDonation).getTime() + GAP_DAYS * 86400000).toISOString().slice(0, 10) : null);
const findDonor = (ref) => db.users.find((u) => u.donor && u.donor.active && isActive(u) && refOf(u.nhrId) === ref);

/* ----- Notifications and audit ----- */
app.get("/api/notifications", (req, res) => {
  const x = auth(req, res, ["nid", "brn", "doctor"]); if (!x) return;
  const list = (db.notifs[x.nhrId] || []).slice(0, 30);
  res.json({ ok: true, list, unread: list.filter((n) => !n.read).length });
});
app.post("/api/notifications/read", (req, res) => {
  const x = auth(req, res, ["nid", "brn", "doctor"]); if (!x) return;
  (db.notifs[x.nhrId] || []).forEach((n) => { n.read = true; }); save();
  res.json({ ok: true });
});
app.get("/api/patient/audit", (req, res) => {
  const x = auth(req, res, ["nid", "brn"]); if (!x) return;
  res.json({ ok: true, list: db.donorViews.filter((v) => v.donorId === x.nhrId).slice(-30).reverse().map((v) => ({
    who: { en: v.who, bn: v.who },
    what: { en: "Viewed your blood donor phone number", bn: "আপনার রক্তদাতা ফোন নম্বর দেখেছেন" },
    at: v.at
  })) });
});

/* ----- Donor profile ----- */
app.get("/api/donor/me", (req, res) => {
  const x = auth(req, res, ["nid"]); if (!x) return;
  const d = (userOf(x) || {}).donor || null;
  const ready = d ? eligibleNow(d) : false;
  res.json({ ok: true, donor: d, ready, next: d && !ready && d.lastDonation ? nextDate(d) : null });
});

app.post("/api/donor/join", (req, res) => {
  const x = auth(req, res, ["nid"]); if (!x) return;
  const u = userOf(x);
  if (!u || !u.dob || ageOf(u.dob) < 18 || ageOf(u.dob) > 60) return bad(res, "dpAdultOnly", 403);
  if (!(req.body && req.body.confirm)) return bad(res, "serverErr");
  const old = u.donor || {};
  u.donor = { active: true, available: true, showPhone: old.showPhone !== false, lastDonation: old.lastDonation || null, donations: old.donations || 0, joinedAt: old.joinedAt || new Date().toISOString() };
  save(); res.json({ ok: true });
});

app.post("/api/donor/leave", (req, res) => {
  const x = auth(req, res, ["nid"]); if (!x) return;
  const u = userOf(x); if (u && u.donor) { u.donor.active = false; save(); }
  res.json({ ok: true });
});

app.post("/api/donor/update", (req, res) => {
  const x = auth(req, res, ["nid"]); if (!x) return;
  const u = userOf(x), b = req.body || {};
  if (!u || !u.donor) return bad(res, "serverErr", 404);
  if (typeof b.available === "boolean") u.donor.available = b.available;
  if (typeof b.showPhone === "boolean") u.donor.showPhone = b.showPhone;
  save(); res.json({ ok: true });
});

app.post("/api/donor/donated", (req, res) => {
  const x = auth(req, res, ["nid"]); if (!x) return;
  const u = userOf(x), date = s(req.body && req.body.date);
  if (!u || !u.donor) return bad(res, "serverErr", 404);
  const ok = /^\d{4}-\d{2}-\d{2}$/.test(date) && !isNaN(new Date(date)) && new Date(date) <= new Date() && (!u.donor.lastDonation || date > u.donor.lastDonation);
  if (!ok) return bad(res, "dpBadDate");
  u.donor.lastDonation = date; u.donor.donations = (u.donor.donations || 0) + 1;
  save(); res.json({ ok: true });
});

/* ----- Find donors ----- */
app.get("/api/donor/search", (req, res) => {
  const x = auth(req, res, ["nid", "doctor"]); if (!x) return;
  if (limited("srch:" + x.nhrId, 40, 10 * 60000)) return bad(res, "tooMany", 429);
  const group = s(req.query.group), district = s(req.query.district);
  if (group && !CAN_RECEIVE[group]) return bad(res, "serverErr");
  const list = db.users
    .filter((u) => u.donor && u.donor.active && isActive(u) && u.nhrId !== x.nhrId && (!group || CAN_RECEIVE[group].includes(u.bloodGroup)) && (!district || u.district === district))
    .map((u) => {
      const ok = eligibleNow(u.donor);
      return { ref: refOf(u.nhrId), name: u.fullName, group: u.bloodGroup, exact: u.bloodGroup === group, district: u.district, available: ok, nextDate: ok ? null : nextDate(u.donor), lastDonation: u.donor.lastDonation, donations: u.donor.donations || 0, showPhone: u.donor.showPhone !== false };
    })
    .sort((a, b) => (b.available - a.available) || (b.exact - a.exact) || a.name.localeCompare(b.name));
  res.json({ ok: true, list: list.slice(0, 100) });
});

app.post("/api/donor/reveal", (req, res) => {
  const x = auth(req, res, ["nid", "doctor"]); if (!x) return;
  if (limited("rev:" + x.nhrId, 10, 3600000)) return bad(res, "tooMany", 429);
  const d = findDonor(s(req.body && req.body.ref));
  if (!d) return bad(res, "serverErr", 404);
  if (d.donor.showPhone === false) return bad(res, "noNumber", 403);
  const who = (userOf(x) || {}).fullName || x.name;
  db.donorViews.push({ donorId: d.nhrId, who, at: new Date().toISOString() });
  if (db.donorViews.length > 2000) db.donorViews.splice(0, db.donorViews.length - 2000);
  notify(d.nhrId, { type: "warn", kind: "view", text: { en: who + " viewed your blood donor phone number.", bn: who + " আপনার রক্তদাতা ফোন নম্বর দেখেছেন।" } });
  save();
  res.json({ ok: true, phone: d.phone });
});

app.post("/api/donor/request", (req, res) => {
  const x = auth(req, res, ["nid", "doctor"]); if (!x) return;
  if (limited("ask:" + x.nhrId, 10, 3600000)) return bad(res, "tooMany", 429);
  const d = findDonor(s(req.body && req.body.ref)), me = userOf(x), group = s(req.body && req.body.group);
  if (!d || !me || !CAN_RECEIVE[group]) return bad(res, "serverErr", 404);
  notify(d.nhrId, { type: "warn", kind: "ask", text: {
    en: me.fullName + " (" + me.phone + ") needs " + group + " blood and asked you to contact them.",
    bn: me.fullName + " (" + me.phone + ") " + group + " রক্ত খুঁজছেন এবং আপনাকে যোগাযোগ করতে অনুরোধ করেছেন।" } });
  save(); res.json({ ok: true });
});

/* ----- Urgent blood requests ----- */
app.post("/api/blood/requests", (req, res) => {
  const x = auth(req, res, ["nid", "doctor"]); if (!x) return;
  if (limited("brq:" + x.nhrId, 5, 3600000)) return bad(res, "tooMany", 429);
  const b = req.body || {}, u = userOf(x);
  const group = s(b.group), district = s(b.district), urgency = b.urgency === "urgent" ? "urgent" : "normal";
  const units = Math.min(10, Math.max(1, parseInt(b.units, 10) || 1));
  if (!u || !CAN_RECEIVE[group] || !district) return bad(res, "rqNeed");
  const r = { id: rand(6).toString("hex"), userId: u.nhrId, name: u.fullName, phone: u.phone, group, district, hospital: s(b.hospital).slice(0, 80), note: s(b.note).slice(0, 200), urgency, units, createdAt: new Date().toISOString(), status: "open", responses: [] };
  db.bloodRequests.unshift(r);
  if (db.bloodRequests.length > 200) db.bloodRequests.length = 200;

  let n = 0;
  db.users.forEach((d) => {
    if (d.donor && d.donor.active && isActive(d) && d.nhrId !== u.nhrId && d.district === district && CAN_RECEIVE[group].includes(d.bloodGroup) && eligibleNow(d.donor)) {
      notify(d.nhrId, { type: urgency === "urgent" ? "warn" : "info", kind: "blood", requestId: r.id, text: {
        en: (urgency === "urgent" ? "URGENT: " : "") + group + " blood needed in " + district + (r.hospital ? " at " + r.hospital : "") + ".",
        bn: (urgency === "urgent" ? "জরুরি: " : "") + district + (r.hospital ? " (" + r.hospital + ")" : "") + " এলাকায় " + group + " রক্ত দরকার।" } });
      n++;
    }
  });
  save(); res.json({ ok: true, id: r.id, notified: n });
});

app.get("/api/blood/requests", (req, res) => {
  const x = auth(req, res, ["nid", "doctor"]); if (!x) return;
  const cutoff = Date.now() - 14 * 86400000;
  const list = db.bloodRequests
    .filter((r) => r.status === "open" && new Date(r.createdAt) > cutoff)
    .map((r) => {
      const mine = r.userId === x.nhrId, responded = r.responses.some((v) => v.userId === x.nhrId);
      return { id: r.id, name: r.name, group: r.group, district: r.district, hospital: r.hospital, note: r.note, urgency: r.urgency, units: r.units, createdAt: r.createdAt, mine, responded,
        phone: responded ? r.phone : undefined,
        responders: mine ? r.responses.map((v) => ({ name: v.name, phone: v.phone, group: v.group })) : undefined };
    })
    .sort((a, b) => ((b.urgency === "urgent") - (a.urgency === "urgent")) || (new Date(b.createdAt) - new Date(a.createdAt)));
  res.json({ ok: true, list });
});

app.post("/api/blood/requests/:id/respond", (req, res) => {
  const x = auth(req, res, ["nid"]); if (!x) return;
  const u = userOf(x), r = db.bloodRequests.find((v) => v.id === req.params.id && v.status === "open");
  if (!r) return bad(res, "serverErr", 404);
  if (!u || !u.donor || !u.donor.active) return bad(res, "rqBecome", 403);
  if (!eligibleNow(u.donor)) return bad(res, "notEligible", 403);
  if (r.userId === u.nhrId) return bad(res, "serverErr");
  if (!r.responses.some((v) => v.userId === u.nhrId)) {
    r.responses.push({ userId: u.nhrId, name: u.fullName, phone: u.phone, group: u.bloodGroup, at: new Date().toISOString() });
    notify(r.userId, { type: "info", kind: "respond", text: {
      en: u.fullName + " (" + u.bloodGroup + ") can donate. Phone: " + u.phone,
      bn: u.fullName + " (" + u.bloodGroup + ") রক্ত দিতে পারবেন। ফোন: " + u.phone } });
    save();
  }
  res.json({ ok: true, phone: r.phone, hospital: r.hospital });
});

app.post("/api/blood/requests/:id/close", (req, res) => {
  const x = auth(req, res, ["nid", "doctor"]); if (!x) return;
  const r = db.bloodRequests.find((v) => v.id === req.params.id && v.userId === x.nhrId);
  if (!r) return bad(res, "serverErr", 404);
  r.status = "closed"; save(); res.json({ ok: true });
});

/* ----- Hospitals ----- */
app.get("/api/hospitals", (req, res) => {
  const x = auth(req, res); if (!x) return;
  res.json({ ok: true, list: db.facilities.filter((f) => f.status === "active" && ["hospital", "clinic"].includes(f.type)).map((f) => {
    const st = db.bloodStock[f.id] || {};
    return { id: f.id, name: f.name, district: f.district, type: cap(f.type), phone: f.phone, address: f.address, schedule: f.schedule || "24/7 Open", services: f.services || [], units: st.units || null, updatedAt: st.updatedAt || null };
  }) });
});

function cleanUnits(src) {
  const units = {};
  for (const g of GROUPS) {
    const n = Number((src || {})[g]);
    if (!Number.isInteger(n) || n < 0 || n > 999) return null;
    units[g] = n;
  }
  return units;
}

app.post("/api/facility/blood-stock", (req, res) => {
  const x = facSes(req); if (!x) return bad(res, "noSession", 401);
  const units = cleanUnits(req.body && req.body.units); if (!units) return bad(res, "serverErr");
  db.bloodStock[x.f.id] = { units, updatedAt: new Date().toISOString(), by: x.f.name };
  save(); res.json({ ok: true });
});

app.post("/api/admin/blood-stock", (req, res) => {
  const x = adminSes(req); if (!x) return bad(res, "noSession", 401);
  const f = db.facilities.find((v) => v.id === s(req.body && req.body.facilityId)); if (!f) return bad(res, "noUser", 404);
  const units = cleanUnits(req.body.units); if (!units) return bad(res, "serverErr");
  db.bloodStock[f.id] = { units, updatedAt: new Date().toISOString(), by: x.name };
  save(); res.json({ ok: true });
});

/* ---------- Cleanup Tasks & Server Launch ---------- */
function purgeExpired() {
  const now = Date.now(); let changed = false;
  for (const u of db.users.slice()) {
    if (u.status !== "pending_delete" || !u.deleteAfter || new Date(u.deleteAfter).getTime() > now) continue;
    db.credentials = db.credentials.filter((c) => c.userId !== u.nhrId);
    db.records = db.records.filter((r) => r.nhrId !== u.nhrId);
    delete db.notifs[u.nhrId];
    db.donorViews = db.donorViews.filter((v) => v.donorId !== u.nhrId);
    db.bloodRequests = db.bloodRequests.filter((r) => r.userId !== u.nhrId);
    if (u.doctor) { Object.assign(u, { patientActive: false, passwordHash: null, status: "active", bloodGroup: "", emergency: {} }); delete u.deleteAfter; delete u.donor; }
    else db.users = db.users.filter((x) => x !== u);
    changed = true;
  }
  if (changed) save();
}

if (AUTO_VERIFY_DOCTORS) { db.users.forEach((u) => { if (u.doctor && u.doctor.status === "pending") u.doctor.status = "verified"; }); save(); }
purgeExpired(); setInterval(purgeExpired, 3600000);

app.listen(PORT, () => {
  console.log(`🚀 NHR BD Server is running at http://localhost:${PORT}`);
  console.log(PUBLIC_URL ? "Phone link base: " + PUBLIC_URL : "PUBLIC_URL is not set. The phone fingerprint QR needs it (put it in your .env file).");
  if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) console.log("EMAIL_USER / EMAIL_PASS are not set, so OTP emails will not be sent.");
});