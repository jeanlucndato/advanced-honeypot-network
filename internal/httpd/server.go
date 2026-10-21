package httpd

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"advance-honeypot-network/internal/event"
	"advance-honeypot-network/internal/sanitize"
	"advance-honeypot-network/internal/types"
)

func StartServer(port string) {
	fmt.Printf("🕸️  HTTP Honeypot active on port %s...\n", port)
	addr := "127.0.0.1:" + port
	if configured := os.Getenv("HIVE_HTTP_ADDR"); configured != "" {
		addr = configured
	}
	server := &http.Server{Addr: addr, Handler: newHandler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("HTTP server failed: %v", err)
	}
}

func newHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /__hive/click", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		var click struct {
			Target string `json:"target"`
		}
		if err := json.NewDecoder(r.Body).Decode(&click); err != nil || strings.TrimSpace(click.Target) == "" {
			http.Error(w, "invalid click event", http.StatusBadRequest)
			return
		}
		target := strings.TrimSpace(click.Target)
		if len(target) > 512 {
			target = target[:512]
		}
		publishHTTPEvent(r, "link_click", sanitize.Redact("LINK CLICK "+target))
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /__hive/contact", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		var submitted map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&submitted); err != nil {
			http.Error(w, "invalid form submission", http.StatusBadRequest)
			return
		}
		fields := make([]string, 0, 3)
		for _, name := range []string{"name", "email", "message"} {
			if _, ok := submitted[name]; ok {
				fields = append(fields, name)
			}
		}
		if len(fields) == 0 {
			http.Error(w, "no supported fields", http.StatusBadRequest)
			return
		}
		publishHTTPEvent(r, "form_submit", fmt.Sprintf("Contact form submitted; fields: %s (values not retained)", strings.Join(fields, ", ")))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, `{"ok":true}`)
	})

	// Capture All routes
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		ip, sourcePort, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr
		}

		requestPath := r.URL.Path
		if r.URL.RawQuery != "" {
			requestPath += "?" + r.URL.RawQuery
		}
		payload := sanitize.Redact(fmt.Sprintf("%s %s", r.Method, requestPath))

		// Capture User-Agent
		if ua := r.Header.Get("User-Agent"); ua != "" {
			payload += fmt.Sprintf(" (UA: %s)", ua)
		}

		// Capture Body if POST
		if r.Body != nil && r.Method != http.MethodGet && r.Method != http.MethodHead {
			r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
			body, _ := io.ReadAll(r.Body)
			if len(body) > 0 {
				payload += fmt.Sprintf(" | Body: %s", sanitize.Redact(string(body)))
			}
		}

		// Detect if it's a known exploit attempt path
		eventType := "web_scan"
		if r.URL.Query().Has("__hive_click") {
			eventType = "link_click"
			if target := r.URL.Query().Get("__hive_target"); target != "" {
				payload = sanitize.Redact("LINK CLICK " + target)
			}
		} else if strings.Contains(r.URL.Path, "wp-login") || strings.Contains(r.URL.Path, "phpmyadmin") || strings.Contains(r.URL.Path, ".env") {
			eventType = "exploit_attempt"
		}

		if eventType == "link_click" {
			publishHTTPEvent(r, eventType, payload)
		} else {
			event.GlobalBus.Publish(types.Event{AttackerIP: ip, AttackerPort: sourcePort, Service: "http", EventType: eventType, Payload: payload})
		}

		// Always return 200 OK with a fake generic response to keep them engaged
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, decoyPage(r.URL.Path))
	})

	return mux
}

func publishHTTPEvent(r *http.Request, eventType, payload string) {
	ip, sourcePort, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	event.GlobalBus.Publish(types.Event{AttackerIP: ip, AttackerPort: sourcePort, Service: "http", EventType: eventType, Payload: sanitize.Redact(payload)})
}

func decoyPage(path string) string {
	if strings.HasSuffix(strings.ToLower(path), "/wp-login.php") || strings.EqualFold(path, "/wp-login.php") {
		return `<!doctype html><html><head><title>Log In &lsaquo; WordPress</title></head><body><main><h1>WordPress</h1><form method="post" action="/wp-login.php"><label>Username or Email Address<input name="log" autocomplete="username"></label><label>Password<input type="password" name="pwd" autocomplete="current-password"></label><button type="submit">Log In</button><input type="hidden" name="redirect_to" value="/wp-admin/"></form></main></body></html>`
	}
	return inverseHackerLandingPage
}

const inverseHackerLandingPage = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="theme-color" content="#080d19">
  <meta name="description" content="inversehacker helps security teams think like the people testing their defenses.">
  <title>inversehacker — Think like the threat</title>
  <style>
    :root{color-scheme:dark;--bg:#080d19;--panel:#101828;--text:#f4f7fb;--muted:#9aa8bc;--line:#263349;--lime:#c3f36b;--cyan:#5de3d0;--purple:#9d8cff}
    *{box-sizing:border-box}
    html{scroll-behavior:smooth}
    body{margin:0;background:var(--bg);color:var(--text);font:16px/1.6 Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
    a{color:inherit;text-decoration:none}
    .wrap{width:min(1160px,calc(100% - 48px));margin:auto}
    .topline{height:36px;background:#0d1423;border-bottom:1px solid #1d293b;color:#b5c1d1;font-size:11px;letter-spacing:.08em}
    .topline .wrap{height:100%;display:flex;align-items:center;justify-content:space-between}
    .pulse{display:inline-flex;align-items:center;gap:9px}.pulse i{width:7px;height:7px;border-radius:50%;background:var(--lime);box-shadow:0 0 12px #c3f37788}
    header{position:sticky;top:0;z-index:5;background:#080d19eF;border-bottom:1px solid #1b2638;backdrop-filter:blur(16px)}
    nav{height:76px;display:flex;align-items:center;justify-content:space-between;gap:26px}
    .menu-toggle{display:none;border:1px solid #344357;border-radius:7px;background:#111b29;color:#eaf1f8;padding:8px 10px;font:inherit;font-size:12px;cursor:pointer}
    .brand{display:flex;align-items:center;gap:11px;font-size:17px;font-weight:750;letter-spacing:-.04em}.brand-mark{width:34px;height:34px;display:grid;place-items:center;border:1px solid #43566b;border-radius:10px;color:var(--lime);font-size:19px;background:linear-gradient(145deg,#1b2b3e,#101722)}.brand b{font-weight:750}.brand em{font-style:normal;color:var(--lime)}
    .navlinks{display:flex;align-items:center;gap:30px;color:#bdc7d5;font-size:13px}.navlinks a:hover{color:var(--lime)}
    .nav-cta,.button{display:inline-flex;align-items:center;justify-content:center;gap:10px;padding:11px 17px;border-radius:7px;background:var(--lime);color:#10180b;font-weight:750;font-size:13px;transition:transform .18s,background .18s}.nav-cta:hover,.button:hover{transform:translateY(-2px);background:#d1fa82}
    .hero{position:relative;overflow:hidden;padding:90px 0 76px;background:radial-gradient(ellipse at 75% 35%,#16314266 0,transparent 42%),linear-gradient(180deg,#0a1120,#080d19)}
    .hero:before{position:absolute;content:"";inset:0;background-image:linear-gradient(#70809a0c 1px,transparent 1px),linear-gradient(90deg,#70809a0c 1px,transparent 1px);background-size:56px 56px;mask-image:linear-gradient(90deg,transparent 5%,#000 80%)}
    .hero-grid{position:relative;display:grid;grid-template-columns:1.08fr .92fr;align-items:center;gap:54px}
    .eyebrow{display:inline-flex;align-items:center;gap:9px;color:var(--lime);font-size:11px;font-weight:750;letter-spacing:.14em;text-transform:uppercase}.eyebrow:before{content:"";width:19px;height:1px;background:var(--lime)}
    h1{max-width:670px;margin:20px 0 20px;font-size:clamp(43px,6vw,72px);line-height:1.03;letter-spacing:-.065em}h1 span{color:var(--lime)}
    .intro{max-width:580px;margin:0;color:#aeb9c9;font-size:17px;line-height:1.75}
    .hero-actions{display:flex;align-items:center;gap:22px;margin-top:32px}.text-link{display:inline-flex;align-items:center;gap:9px;color:#e5ecf5;font-size:13px;font-weight:650}.text-link span{color:var(--lime);font-size:18px}
    .trustline{display:flex;align-items:center;gap:13px;margin-top:44px;color:#8d9bb0;font-size:11px}.avatars{display:flex}.avatars i{display:grid;place-items:center;width:26px;height:26px;margin-left:-6px;border:2px solid var(--bg);border-radius:50%;background:#23364b;color:#d8e3ef;font-size:9px;font-style:normal}.avatars i:first-child{margin-left:0;background:#344a3e}.avatars i:last-child{background:#443c66}
    .visual{position:relative;min-height:390px;display:grid;place-items:center}.orbit{position:absolute;width:320px;height:320px;border:1px solid #26394c;border-radius:50%;box-shadow:0 0 70px #2cd8bb12,inset 0 0 65px #23384a22}.orbit:before,.orbit:after{position:absolute;content:"";border:1px dashed #42566b;border-radius:50%;inset:28px}.orbit:after{inset:66px;border-style:solid;border-color:#2f455a}.core{position:relative;z-index:1;width:154px;height:154px;display:grid;place-items:center;border:1px solid #5d7782;border-radius:36px;background:linear-gradient(145deg,#172b3a,#0d1522);box-shadow:0 0 65px #63e4cc1d;transform:rotate(-8deg)}.core svg{width:76px;height:76px;transform:rotate(8deg)}
    .float-card{position:absolute;z-index:2;display:flex;align-items:center;gap:11px;padding:12px 14px;border:1px solid #2a3b50;border-radius:9px;background:#101a29eF;box-shadow:0 15px 45px #0005;font-size:11px}.float-card strong{display:block;color:#eaf1f9;font-size:11px}.float-card small{display:block;color:#8191a8;font-size:10px}.float-icon{width:32px;height:32px;display:grid;place-items:center;border-radius:8px;background:#1a302a;color:var(--lime);font-size:16px}.fc-one{top:35px;right:0}.fc-two{bottom:48px;left:0}.fc-three{top:48%;right:-15px}.signal{position:absolute;width:7px;height:7px;border-radius:50%;background:var(--cyan);box-shadow:0 0 18px var(--cyan)}.s-one{top:10%;left:28%}.s-two{bottom:15%;right:24%;background:var(--purple);box-shadow:0 0 18px var(--purple)}
    .proof{border-block:1px solid #1d293b;background:#0b111e}.proof-grid{display:grid;grid-template-columns:repeat(4,1fr);padding:25px 0}.proof-item{text-align:center;border-right:1px solid #263144}.proof-item:last-child{border:0}.proof-item strong{display:block;color:#eaf1f8;font-size:17px}.proof-item span{color:#8492a8;font-size:10px;letter-spacing:.07em;text-transform:uppercase}
    section.content{padding:92px 0}.section-head{max-width:690px;margin:0 auto 42px;text-align:center}.section-head h2,.split h2{margin:13px 0;font-size:clamp(30px,4vw,43px);line-height:1.13;letter-spacing:-.05em}.section-head p,.split p{color:var(--muted);font-size:14px;line-height:1.8}
    .cards{display:grid;grid-template-columns:repeat(3,1fr);gap:15px}.card{min-height:230px;padding:24px;border:1px solid #253248;border-radius:11px;background:linear-gradient(150deg,#121d2d,#0d1421);transition:transform .2s,border-color .2s}.card:hover{transform:translateY(-4px);border-color:#53664f}.card-icon{width:40px;height:40px;display:grid;place-items:center;margin-bottom:22px;border:1px solid #344757;border-radius:10px;background:#15232c;color:var(--cyan);font-size:18px}.card:nth-child(2) .card-icon{color:var(--purple)}.card:nth-child(3) .card-icon{color:var(--lime)}.card h3{margin:0 0 8px;font-size:17px;letter-spacing:-.02em}.card p{margin:0;color:#94a2b6;font-size:12px;line-height:1.75}
    .campaign{padding:0 0 70px}.campaign-box{position:relative;overflow:hidden;display:grid;grid-template-columns:1fr auto;align-items:center;gap:30px;padding:42px 48px;border:1px solid #34443d;border-radius:13px;background:radial-gradient(ellipse at 90% 20%,#bbef6120,transparent 40%),linear-gradient(120deg,#111d27,#101925)}.campaign-box h2{max-width:650px;margin:12px 0;font-size:clamp(26px,3.8vw,38px);line-height:1.15;letter-spacing:-.045em}.campaign-box p{max-width:600px;margin:0;color:#a2b0c1;font-size:13px;line-height:1.75}.campaign-box .button{white-space:nowrap}
    .contact{padding:20px 0 90px}.contact-grid{display:grid;grid-template-columns:.8fr 1.2fr;gap:55px;align-items:start}.contact-copy h2{margin:13px 0;font-size:clamp(28px,4vw,42px);line-height:1.1;letter-spacing:-.05em}.contact-copy p{color:var(--muted);font-size:14px;line-height:1.8}.contact-form{display:grid;grid-template-columns:1fr 1fr;gap:14px;padding:24px;border:1px solid #29384d;border-radius:11px;background:linear-gradient(145deg,#121d2c,#0d1420)}.contact-form label{display:grid;gap:7px;color:#b1bdcf;font-size:11px}.contact-form label:nth-child(3){grid-column:1/-1}.contact-form input,.contact-form textarea{width:100%;box-sizing:border-box;border:1px solid #304056;border-radius:6px;padding:10px 11px;background:#090f19;color:#edf3f9;font:13px/1.5 inherit}.contact-form textarea{min-height:120px;resize:vertical}.contact-form input:focus,.contact-form textarea:focus{outline:2px solid #5de3d088;border-color:#5de3d0}.contact-submit{justify-self:start;border:0;cursor:pointer}.contact-submit:disabled{opacity:.6;cursor:wait}.form-status{grid-column:1/-1;min-height:20px;margin:0;color:var(--cyan);font-size:12px}.form-status.error{color:#ff9c9c}
    footer{border-top:1px solid #202b3e;padding:28px 0 36px;color:#8290a4;font-size:11px}.footer-row{display:flex;justify-content:space-between;align-items:center;gap:20px}.footer-brand{color:#edf3f9;font-size:14px;font-weight:750}.footer-brand em{color:var(--lime);font-style:normal}.footer-links{display:flex;gap:22px}
    .contact-form input,.contact-form textarea{font-family:inherit;font-size:13px;line-height:1.5}
    @media(max-width:800px){nav{position:relative}.menu-toggle{display:inline-flex}.navlinks{display:none;position:absolute;top:66px;right:0;z-index:8;min-width:190px;flex-direction:column;align-items:stretch;gap:0;padding:8px;border:1px solid #2c3b50;border-radius:9px;background:#111a28;box-shadow:0 16px 35px #0008}.nav-open .navlinks{display:flex}.navlinks a{padding:10px 12px}.navlinks a:nth-child(2),.navlinks a:nth-child(3){display:block}.hero{padding:64px 0 52px}.hero-grid{grid-template-columns:1fr;gap:22px}.visual{min-height:330px}.orbit{width:270px;height:270px}.core{width:130px;height:130px}.fc-one{right:5%}.fc-two{left:5%}.fc-three{right:0}.proof-grid{grid-template-columns:repeat(2,1fr);row-gap:22px}.proof-item:nth-child(2){border:0}.cards{grid-template-columns:1fr}.card{min-height:0}.campaign-box{grid-template-columns:1fr;padding:30px}.campaign-box .button{justify-self:start}.contact-grid{grid-template-columns:1fr;gap:20px}}
    @media(max-width:500px){.wrap{width:min(100% - 32px,1160px)}.topline .wrap span:last-child{display:none}nav{height:66px}.nav-cta{padding:9px 12px;font-size:11px}.hero{padding-top:52px}h1{font-size:46px}.intro{font-size:15px}.hero-actions{align-items:flex-start;flex-direction:column;gap:15px}.trustline{margin-top:30px}.visual{min-height:285px}.orbit{width:230px;height:230px}.core{width:108px;height:108px;border-radius:28px}.core svg{width:58px;height:58px}.float-card{padding:9px 10px}.fc-one{top:12px}.fc-two{bottom:23px}.fc-three{right:-6px}.proof-grid{padding:20px 0}.proof-item strong{font-size:15px}.proof-item span{font-size:9px}.content{padding:65px 0!important}.campaign{padding-bottom:48px}.contact{padding:12px 0 65px}.contact-form{grid-template-columns:1fr;padding:18px}.contact-form label:nth-child(3){grid-column:auto}.form-status{grid-column:auto}.footer-row{align-items:flex-start;flex-direction:column}.footer-links{gap:15px}}
    @media(prefers-reduced-motion:reduce){html{scroll-behavior:auto}*,*:before,*:after{transition:none!important}}
  </style>
</head>
<body>
  <div class="topline"><div class="wrap"><span class="pulse"><i></i> INDEPENDENT SECURITY RESEARCH &amp; DEFENSE</span><span>BUILT FOR THE REAL WORLD · EST. 2018</span></div></div>
  <header><nav class="wrap" aria-label="Main navigation">
    <a class="brand" href="#top" aria-label="inversehacker home"><span class="brand-mark">↗</span><span>inverse<em>hacker</em></span></a>
    <div class="navlinks" id="site-navigation"><a href="#approach">Our approach</a><a href="#expertise">Expertise</a><a href="#campaign">Research</a><a href="#contact">Contact</a></div>
    <button class="menu-toggle" type="button" aria-controls="site-navigation" aria-expanded="false">Menu</button>
    <a class="nav-cta" href="#campaign">Explore our work <span aria-hidden="true">↗</span></a>
  </nav></header>
  <main id="top">
    <section class="hero"><div class="wrap hero-grid">
      <div><div class="eyebrow">Security from the other side</div><h1>Think like the threat.<br><span>Defend what matters.</span></h1><p class="intro">We help ambitious teams uncover the paths an attacker would take — then make sure those paths lead nowhere.</p>
        <div class="hero-actions"><a class="button" href="#expertise">See how we help <span aria-hidden="true">→</span></a><a class="text-link" href="#approach">Meet the inverse approach <span aria-hidden="true">↘</span></a></div>
        <div class="trustline"><div class="avatars" aria-hidden="true"><i>R</i><i>M</i><i>A</i></div><span>Curious minds. Relentless defenders. One mission.</span></div>
      </div>
      <div class="visual" aria-label="Illustration of a protected digital network">
        <div class="orbit"></div><span class="signal s-one"></span><span class="signal s-two"></span>
        <div class="core"><svg viewBox="0 0 100 100" fill="none" aria-hidden="true"><path d="M50 8 82 20v24c0 22-13 38-32 48C31 82 18 66 18 44V20L50 8Z" stroke="#C3F36B" stroke-width="2.5"/><path d="m36 49 9 9 20-22" stroke="#5DE3D0" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><circle cx="50" cy="49" r="29" stroke="#41586A" stroke-dasharray="3 5"/></svg></div>
        <div class="float-card fc-one"><span class="float-icon">⌁</span><span><strong>Attack surface mapped</strong><small>Know what’s exposed</small></span></div>
        <div class="float-card fc-two"><span class="float-icon">◉</span><span><strong>Human-first defense</strong><small>Built around real behavior</small></span></div>
        <div class="float-card fc-three"><span class="float-icon">↗</span><span><strong>Resilience, verified</strong><small>Evidence over assumptions</small></span></div>
      </div>
    </div></section>
    <section class="proof" aria-label="Our capabilities"><div class="wrap proof-grid">
      <div class="proof-item"><strong>Offense-informed</strong><span>Defensive strategy</span></div><div class="proof-item"><strong>Always curious</strong><span>Independent research</span></div><div class="proof-item"><strong>Human-centered</strong><span>Practical outcomes</span></div><div class="proof-item"><strong>Built for trust</strong><span>Responsible practice</span></div>
    </div></section>
    <section class="content" id="approach"><div class="wrap"><div class="section-head"><div class="eyebrow">A different point of view</div><h2>Understand the move.<br>Change the outcome.</h2><p>Security gets stronger when you see your environment the way an adversary might. We turn that perspective into clear priorities and measurable progress.</p></div>
      <div class="cards" id="expertise">
        <article class="card"><div class="card-icon" aria-hidden="true">⌕</div><h3>Find the blind spots</h3><p>Map exposed assets, test assumptions, and surface the issues that matter before someone else does.</p></article>
        <article class="card"><div class="card-icon" aria-hidden="true">⟲</div><h3>Build attacker-aware teams</h3><p>Give your people practical insight into how real attacks unfold, with exercises grounded in your world.</p></article>
        <article class="card"><div class="card-icon" aria-hidden="true">⌘</div><h3>Make defense measurable</h3><p>Turn findings into a focused plan, validate the fixes, and give leaders a clearer view of risk.</p></article>
      </div>
    </div></section>
    <section class="campaign" id="campaign"><div class="wrap"><div class="campaign-box"><div><div class="eyebrow">The inversehacker field notes</div><h2>Curiosity is a security capability.</h2><p>Explore ideas from the people who study how systems fail — and help teams make them harder to break.</p></div><a class="button" href="#contact">Start a conversation <span aria-hidden="true">→</span></a></div></div></section>
    <section class="contact" id="contact"><div class="wrap contact-grid"><div class="contact-copy"><div class="eyebrow">Make the next move</div><h2>Tell us what you’re working on.</h2><p>Share a little context and the inversehacker team will follow up with a practical next step.</p></div><form class="contact-form" id="contact-form"><label>Name<input name="name" autocomplete="name" required maxlength="120" placeholder="Your name"></label><label>Email<input name="email" type="email" autocomplete="email" required maxlength="254" placeholder="you@example.com"></label><label>What would you like to discuss?<textarea name="message" required maxlength="2000" placeholder="A few details about your security goals..."></textarea></label><button class="button contact-submit" type="submit">Send inquiry <span aria-hidden="true">→</span></button><p class="form-status" aria-live="polite"></p></form></div></section>
  </main>
  <footer><div class="wrap footer-row"><a class="footer-brand" href="#top">inverse<em>hacker</em></a><span>Independent thinking. Resilient systems. Better security.</span><div class="footer-links"><a href="#approach">Approach</a><a href="#expertise">Expertise</a><a href="#campaign">Research</a></div></div></footer>
<script>
  const nav = document.querySelector("header nav");
  const menu = document.querySelector(".menu-toggle");
  menu.addEventListener("click", function () {
    const expanded = menu.getAttribute("aria-expanded") === "true";
    menu.setAttribute("aria-expanded", String(!expanded));
    nav.classList.toggle("nav-open", !expanded);
  });
  document.addEventListener("click", function (event) {
    const link = event.target instanceof Element ? event.target.closest("a") : null;
    if (!link || link.origin !== location.origin) return;
    const destination = new URL(link.href);
    navigator.sendBeacon("/__hive/click", new Blob([JSON.stringify({target: destination.pathname + destination.search + destination.hash})], {type:"application/json"}));
    nav.classList.remove("nav-open");
    menu.setAttribute("aria-expanded", "false");
  }, true);
  document.querySelector("#contact-form").addEventListener("submit", async function (event) {
    event.preventDefault();
    const form = event.currentTarget;
    const button = form.querySelector("button[type=submit]");
    const status = form.querySelector(".form-status");
    button.disabled = true;
    status.classList.remove("error");
    status.textContent = "Sending your inquiry…";
    try {
      const values = Object.fromEntries(new FormData(form).entries());
      const response = await fetch("/__hive/contact", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(values)});
      if (!response.ok) throw new Error("Request failed");
      form.reset();
      status.textContent = "Thanks — your inquiry has been received.";
    } catch (_) {
      status.classList.add("error");
      status.textContent = "We could not send that just now. Please try again.";
    } finally { button.disabled = false; }
  });
</script>
</body>
</html>`
