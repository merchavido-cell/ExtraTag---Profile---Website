(() => {
  "use strict";
  let csrf = document.querySelector('meta[name="csrf"]').content;
  let user = null;
  const $ = (s) => document.querySelector(s);
  const show = (el, on) => { if(el) el.hidden = !on; };
  const COLORS = ["#38bdf8", "#ef4444", "#10b981", "#f59e0b", "#ec4899", "#8b5cf6", "#f43f5e"];
  const SHAPES = ["circle", "square", "pentagon", "hexagon", "heptagon", "octagon"];
  const DARK_TEXT = ["#38bdf8", "#10b981", "#f59e0b"];
  const VIEWS = ["auth", "home", "edit", "avatar", "security"];

  function say(text, ok) {
    const m = $("#msg");
    if (!m) return;
    m.textContent = text || "";
    m.className = "msg " + (ok ? "ok" : "err");
    show(m, !!text);
  }

  async function api(path, method, body) {
    const opt = { method: method || "GET", credentials: "same-origin", headers: {} };
    if (opt.method !== "GET") {
      opt.headers["Content-Type"] = "application/json";
      opt.headers["X-CSRF-Token"] = csrf;
      opt.body = JSON.stringify(body || {});
    }
    let data = {};
    try { data = await (await fetch(path, opt)).json(); } catch (e) { return { ok: false, error: "Network error." }; }
    if (data.csrf) csrf = data.csrf;
    return data;
  }
  const formData = (f) => Object.fromEntries(new FormData(f).entries());
  async function busy(btn, fn) { if(btn) btn.disabled = true; try { await fn(); } finally { if(btn) btn.disabled = false; } }

  // ---------- views
  function go(name) {
    VIEWS.forEach((v) => show($("#v-" + v), v === name));
    document.querySelectorAll(".side-item[data-go]").forEach((b) => b.classList.toggle("on", b.dataset.go === name));
    if (name === "avatar") initAvatar();
    say("");
  }
  document.querySelectorAll(".side-item[data-go]").forEach((b) => { b.onclick = () => go(b.dataset.go); });
  const avatarBtn = $("#avatar-btn");
  if (avatarBtn) avatarBtn.onclick = () => go("edit");

  function paintAvatar(el, base, u, color, shape) {
    if (!el) return;
    el.className = base + " " + shape;
    el.style.backgroundColor = color;
    el.style.color = DARK_TEXT.includes(color) ? "#0f172a" : "#ffffff";
    el.textContent = (u.firstName[0] || "?").toUpperCase();
  }

  function enter(u) {
    user = u;
    show($("#sidebar"), true); show($("#avatar-btn"), true);
    paintAvatar($("#avatar-btn"), "profile-avatar", u, u.avatarColor, u.avatarShape);
    if ($("#welcome")) $("#welcome").textContent = "Welcome " + u.firstName + "!";
    
    const f = $("#f-profile");
    if (f) {
      const elems = f.elements;
      if (elems.firstName) elems.firstName.value = u.firstName;
      if (elems.lastName) elems.lastName.value = u.lastName;
      if (elems.language) elems.language.value = u.language;
      if ($("#ro-email")) $("#ro-email").value = u.exmail || u.email;
      if ($("#ro-user")) $("#ro-user").value = u.username;
    }
    show($("#mbx"), !u.exmail);
    go("home");
  }

  function leave() {
    user = null;
    show($("#sidebar"), false); show($("#avatar-btn"), false);
    show($("#auth-main"), true); show($("#auth-sent"), false); show($("#auth-verify"), false);
    tab(false); go("auth");
  }

  // ---------- auth
  function tab(signup) {
    if ($("#t-signup")) $("#t-signup").classList.toggle("on", signup);
    if ($("#t-login")) $("#t-login").classList.toggle("on", !signup);
    show($("#f-signup"), signup); show($("#f-login"), !signup);
    say("");
  }
  if ($("#t-signup")) $("#t-signup").onclick = () => tab(true);
  if ($("#t-login")) $("#t-login").onclick = () => tab(false);
  
  if ($("#b-eye")) {
    $("#b-eye").onclick = () => {
      const i = $("#f-login").elements.password;
      const on = i.type === "password";
      i.type = on ? "text" : "password"; 
      $("#b-eye").textContent = on ? "🔒" : "👁";
    };
  }

  if ($("#f-signup")) {
    $("#f-signup").elements.password.addEventListener("input", (e) => {
      const p = e.target.value;
      let sc = Math.min(p.length, 20) / 20 * 70;
      sc += (/[a-z]/.test(p) + /[A-Z]/.test(p) + /\d/.test(p) + /[^\w\s]/.test(p)) * 7.5;
      if ($("#bar")) $("#bar").style.width = sc + "%";
      if ($("#bar")) $("#bar").style.backgroundColor = sc < 40 ? "#ef4444" : sc < 75 ? "#f59e0b" : "#10b981";
      if ($("#strength")) $("#strength").textContent = !p ? "" : sc < 75 ? "OK – longer is stronger" : "Strong";
    });

    $("#f-signup").addEventListener("submit", (e) => {
      e.preventDefault();
      const f = e.target;
      busy(f.querySelector("button[type=submit]"), async () => {
        const d = formData(f);
        const r = await api("/api/signup", "POST", d);
        if (!r.ok) return say(r.error, false);
        f.reset(); if ($("#bar")) $("#bar").style.width = "0"; if ($("#strength")) $("#strength").textContent = "";
        if ($("#sent-to")) $("#sent-to").textContent = d.email;
        if ($("#f-verify")) $("#f-verify").dataset.email = d.email;
        show($("#auth-main"), false); show($("#auth-sent"), false); show($("#auth-verify"), true);
        say("");
      });
    });
  }

  if ($("#f-verify")) {
    $("#f-verify").addEventListener("submit", (e) => {
      e.preventDefault();
      const f = e.target;
      busy(f.querySelector("button[type=submit]"), async () => {
        const email = f.dataset.email || "";
        const r = await api("/api/verify", "POST", { email, code: formData(f).code });
        if (!r.ok) return say(r.error, false);
        enter(r.user);
        say(r.message || "Verified!", true);
      });
    });
  }

  if ($("#b-back")) {
    $("#b-back").onclick = () => { show($("#auth-verify"), false); show($("#auth-main"), true); tab(false); };
  }

  if ($("#f-login")) {
    $("#f-login").addEventListener("submit", (e) => {
      e.preventDefault();
      const f = e.target;
      busy(f.querySelector("button[type=submit]"), async () => {
        const r = await api("/api/login", "POST", formData(f));
        f.reset();
        if (!r.ok) return say(r.error, false);
        enter(r.user);
      });
    });
  }

  // ---------- profile
  if ($("#f-profile")) {
    $("#f-profile").addEventListener("submit", (e) => {
      e.preventDefault();
      busy(e.target.querySelector("button"), async () => {
        const d = formData(e.target);
        d.language = d.language || user.language || "en";
        const r = await api("/api/profile", "POST", { ...d, avatarShape: user.avatarShape, avatarColor: user.avatarColor });
        if (!r.ok) return say(r.error, false);
        const me = await api("/api/me");
        if (me.ok) enter(me.user);
        say("Profile updated successfully!", true);
      });
    });
  }

  // ---------- avatar builder
  let pickColor = COLORS[0], pickShape = "circle", built = false;
  function drawBuilder() {
    paintAvatar($("#preview"), "shape", user, pickColor, pickShape);
    document.querySelectorAll(".color-circle").forEach((b) => b.classList.toggle("on", b.dataset.c === pickColor));
    document.querySelectorAll(".menu-shape").forEach((b) => b.classList.toggle("on", b.dataset.s === pickShape));
  }
  function initAvatar() {
    if (!built && user) {
      COLORS.forEach((c) => {
        const b = document.createElement("button");
        b.type = "button"; b.className = "color-circle"; b.dataset.c = c; b.setAttribute("aria-label", "Color " + c);
        b.style.backgroundColor = c;
        b.onclick = () => { pickColor = c; drawBuilder(); };
        if ($("#colors")) $("#colors").appendChild(b);
      });
      SHAPES.forEach((s) => {
        const b = document.createElement("button");
        b.type = "button"; b.className = "menu-shape " + s; b.dataset.s = s; b.setAttribute("aria-label", s);
        b.onclick = () => { pickShape = s; drawBuilder(); };
        if ($("#shapes")) $("#shapes").appendChild(b);
      });
      built = true;
    }
    if(user) {
      pickColor = user.avatarColor; pickShape = user.avatarShape; drawBuilder();
    }
  }
  if ($("#b-avatar")) {
    $("#b-avatar").onclick = (e) => busy(e.target, async () => {
      const r = await api("/api/profile", "POST", { firstName: user.firstName, lastName: user.lastName,
        language: user.language || "en", avatarShape: pickShape, avatarColor: pickColor });
      if (!r.ok) return say(r.error, false);
      const me = await api("/api/me");
      if (me.ok) enter(me.user);
    });
  }

  // ---------- security
  if ($("#f-pw")) {
    $("#f-pw").addEventListener("submit", (e) => {
      e.preventDefault();
      busy(e.target.querySelector("button"), async () => {
        const r = await api("/api/password", "POST", formData(e.target));
        if (r.ok) e.target.reset();
        say(r.ok ? r.message : r.error, r.ok);
      });
    });
  }
  if ($("#b-mbx")) {
    $("#b-mbx").onclick = (e) => busy(e.target, async () => {
      const r = await api("/api/mailbox", "POST", {});
      if (!r.ok) return say(r.error, false);
      show($("#mbx"), false);
      if ($("#ro-email")) $("#ro-email").value = r.exmail;
      say("Mailbox " + r.exmail + " created. Mailbox password (shown once, save it now): " + r.password, true);
    });
  }
  if ($("#b-logout")) {
    $("#b-logout").onclick = async () => { await api("/api/logout", "POST", {}); leave(); say("Signed out.", true); };
  }

  // ---------- start
  async function boot() {
    show($("#app"), true);
    try {
      const me = await api("/api/me");
      if (me.ok) enter(me.user); else leave();
    } catch (err) {
      console.error("Boot error:", err);
      leave(); 
    }
  }
  
  const splash = $("#splash"), logo = $("#splash-logo");
  const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const played = sessionStorage.getItem("introPlayed");
  
  const done = () => { 
    if (splash && splash.parentNode) {
      splash.classList.add("out"); 
      setTimeout(() => splash.remove(), 600); 
    }
  };

  if (played || reduce) { 
    if (splash) splash.remove(); 
    boot(); 
  } else {
    sessionStorage.setItem("introPlayed", "1");
    setTimeout(() => { if(logo) logo.classList.add("in"); }, 100);
    setTimeout(() => { if(logo) logo.classList.add("corner"); }, 1500);
    setTimeout(() => { 
      boot(); 
      done(); 
    }, 2800);
  }
})();