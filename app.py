from flask import Flask
app = Flask(__name__)

# ---------- STYLES ----------
STYLE = """
@import url('https://fonts.googleapis.com/css2?family=Anton&family=Rajdhani:wght@400;600;700&display=swap');

body {
  font-family:'Rajdhani', sans-serif;
  background:#000;
  color:#fff;
  margin:0;
  padding:0;
  border-left:10px solid #c8102e;
  border-right:10px solid #c8102e;
  min-height:100vh;
  opacity:0;
  transition:opacity .5s ease-in-out;
}
body.loaded {opacity:1;}

header {
  background:#c8102e;
  display:flex;
  justify-content:space-between;
  align-items:center;
  padding:15px 50px;
  box-shadow:0 2px 12px rgba(0,0,0,.5);
}
header h1 {
  font-family:'Anton', sans-serif;
  font-size:3rem;
  color:#000;
  text-shadow:2px 2px 0 #fff;
  letter-spacing:2px;
  transition:transform .3s ease, text-shadow .3s ease;
  cursor:pointer;
}
header h1:hover {
  transform:scale(1.05);
  text-shadow:0 0 15px #fff;
}
nav {
  display:flex;
  gap:15px;
}
nav a {
  background:#c8102e;
  color:#000;
  font-family:'Anton', sans-serif;
  text-transform:uppercase;
  padding:10px 20px;
  border-radius:10px;
  border:3px solid #000;
  text-decoration:none;
  box-shadow:0 4px 10px rgba(0,0,0,.5);
  transition:transform .3s ease, box-shadow .3s ease, background .3s;
}
nav a:hover {
  transform:translateY(-5px);
  box-shadow:0 8px 20px rgba(200,16,46,.8);
  background:#ff1e38;
}

.container {
  padding:40px;
  max-width:1200px;
  margin:auto;
}

h2 {
  color:#c8102e;
  font-family:'Anton', sans-serif;
  text-transform:uppercase;
  text-align:center;
  font-size:2.5rem;
  background:#111;
  padding:15px;
  border-radius:15px;
  border:4px solid #c8102e;
  box-shadow:0 0 20px rgba(200,16,46,.4);
}

p {
  font-family:'Rajdhani', sans-serif;
  font-size:1.2rem;
  text-align:center;
  max-width:900px;
  margin:20px auto;
  line-height:1.6em;
  color:#f5f5f5;
}

img.hero {
  width:80%;
  max-width:900px;
  display:block;
  margin:30px auto;
  border-radius:20px;
  box-shadow:0 0 25px rgba(200,16,46,.5);
  transition:.3s;
}
img.hero:hover {
  transform:scale(1.03);
  box-shadow:0 0 35px rgba(200,16,46,.8);
}

footer {
  background:#111;
  text-align:center;
  padding:20px;
  color:#888;
  margin-top:40px;
  border-top:5px solid #c8102e;
}

/* Membership Section */
.card-grid {
  display:flex;
  justify-content:center;
  flex-wrap:wrap;
  gap:30px;
  margin-top:40px;
}
.card {
  background:#c8102e;
  border:4px solid #000;
  border-radius:20px;
  width:280px;
  padding:25px 20px;
  text-align:center;
  box-shadow:0 4px 15px rgba(0,0,0,0.6);
  transition:transform .3s ease, box-shadow .3s ease;
}
.card:hover {
  transform:translateY(-10px) scale(1.05);
  box-shadow:0 8px 25px rgba(200,16,46,.8);
}
.card h3 {
  font-family:'Anton', sans-serif;
  color:#000;
  font-size:1.3rem;
  margin-bottom:10px;
}
.card p {
  color:#fff;
  font-size:1rem;
  line-height:1.4em;
}
.price {
  font-size:1.4rem;
  color:#fff;
  margin-bottom:10px;
  font-weight:bold;
}

/* Payment Section inside card */
.payment-methods {
  margin-top:15px;
  background:#000;
  border:2px solid #fff;
  border-radius:10px;
  padding:10px;
}
.payment-methods h4 {
  color:#fff;
  font-family:'Anton', sans-serif;
  margin-bottom:10px;
  font-size:1rem;
  letter-spacing:1px;
}
.payment-list {
  list-style:none;
  padding:0;
  margin:0;
}
.payment-list li {
  color:#fff;
  font-size:0.95rem;
  margin:4px 0;
  padding:5px;
  background:#c8102e;
  border-radius:6px;
  transition:.2s;
}
.payment-list li:hover {
  background:#ff1e38;
  transform:scale(1.05);
}

@media (max-width:1000px) {
  .card {width:90%; max-width:320px;}
}
"""

# ---------- TRANSITIONS ----------
SCRIPT = """
<script>
document.addEventListener("DOMContentLoaded", ()=>{
  document.body.classList.add("loaded");
  document.querySelectorAll("a").forEach(link=>{
    link.addEventListener("click", e=>{
      if(link.hostname===location.hostname && link.getAttribute("href").startsWith("/")){
        e.preventDefault();
        document.body.classList.remove("loaded");
        setTimeout(()=>{window.location=link.href;},300);
      }
    });
  });
});
</script>
"""

# ---------- HEADER / FOOTER ----------
HEADER = """
<header>
  <h1 onclick="window.location='/'">FIGHT ZONE</h1>
  <nav>
    <a href="/about">About</a>
    <a href="/benefits">Benefits</a>
    <a href="/membership">Membership</a>
  </nav>
</header>
"""
FOOTER = "<footer>© 2025 Fight Zone | Founded by Cynric</footer>"

def page_html(title, body):
    return f"""<!DOCTYPE html>
<html lang='en'>
<head>
<meta charset='UTF-8'>
<meta name='viewport' content='width=device-width,initial-scale=1.0'>
<title>{title} - Fight Zone</title>
<style>{STYLE}</style>
</head>
<body>{HEADER}<div class='container'>{body}</div>{FOOTER}{SCRIPT}</body></html>"""


# ---------- HOME ----------
@app.route("/")
def home():
    body = """
<h2>Welcome to Fight Zone</h2>
<p>Welcome to <strong>Fight Zone</strong> — the ultimate place to explore the power of boxing and fitness.
Discover how boxing can help you achieve strength, discipline, and a healthy lifestyle.</p>

<img src="/static/images/home_image.png" class="hero" alt="Home image">

<p>Boxing is more than a sport — it’s a mindset. Every punch, every round, every drop of sweat brings you closer
to becoming the best version of yourself.</p>
"""
    return page_html("Home", body)


# ---------- ABOUT ----------
@app.route("/about")
def about():
    body = """
<h2>About Fight Zone</h2>
<p><strong>Fight Zone</strong> was founded by <strong>Cynric</strong> to inspire people to embrace fitness through boxing.
Our mission is to educate, motivate, and guide individuals to live stronger, healthier lives — both mentally and physically.</p>

<img src="/static/images/about_image.png" class="hero" alt="About image">

<p>Boxing builds not only physical strength but also mental toughness, self-confidence, and discipline — qualities that
extend beyond the ring into everyday life.</p>
"""
    return page_html("About", body)


# ---------- BENEFITS ----------
@app.route("/benefits")
def benefits():
    body = """
<h2>Benefits of Boxing</h2>
<p>Boxing offers a range of physical and mental advantages that go beyond the gym. Here are the top benefits:</p>

<div class="card-grid">
  <div class="card">
    <h3>Cardiovascular Health</h3>
    <p>Improves endurance, stamina, and overall heart health.</p>
  </div>
  <div class="card">
    <h3>Coordination & Agility</h3>
    <p>Sharpens reflexes, timing, and body control for faster reactions.</p>
  </div>
  <div class="card">
    <h3>Weight Management</h3>
    <p>Burns fat, builds lean muscle, and tones the entire body.</p>
  </div>
  <div class="card">
    <h3>Confidence & Resilience</h3>
    <p>Boosts self-esteem and mental toughness through discipline.</p>
  </div>
  <div class="card">
    <h3>Stress Relief & Focus</h3>
    <p>Clears the mind, relieves tension, and improves concentration.</p>
  </div>
</div>

<div style='text-align:center;margin-top:60px;'>
  <h3 style='color:#c8102e;font-family:Anton,sans-serif;font-size:1.6rem;'>DEUTERONOMY 20:4</h3>
  <p>"For the Lord your God is the one who goes with you to fight for you against your enemies to give you victory."</p>
</div>
"""
    return page_html("Benefits", body)


# ---------- MEMBERSHIP ----------
@app.route("/membership")
def membership():
    body = """
<h2>Membership Plans</h2>
<p>Choose your plan and join the Fight Zone community today. Get stronger, sharper, and more confident with every session!</p>

<div class="card-grid">
  <div class="card">
    <h3>Basic</h3>
    <div class="price">₱500 / month</div>
    <p>Gym access and beginner boxing classes. Great for starters!</p>
    <div class="payment-methods">
      <h4>Payment Methods</h4>
      <ul class="payment-list">
        <li>💸 GCash</li>
        <li>💳 Maya</li>
        <li>🏦 Online Banking</li>
        <li>💵 Cash</li>
      </ul>
    </div>
  </div>

  <div class="card">
    <h3>Pro</h3>
    <div class="price">₱1,000 / month</div>
    <p>Includes all Basic perks plus 2x personal trainer sessions per month.</p>
    <div class="payment-methods">
      <h4>Payment Methods</h4>
      <ul class="payment-list">
        <li>💸 GCash</li>
        <li>💳 Maya</li>
        <li>🏦 Online Banking</li>
        <li>💵 Cash</li>
      </ul>
    </div>
  </div>

  <div class="card">
    <h3>Elite</h3>
    <div class="price">₱2,000 / month</div>
    <p>VIP access with 4x personal training sessions, diet plan, and sparring sessions.</p>
    <div class="payment-methods">
      <h4>Payment Methods</h4>
      <ul class="payment-list">
        <li>💸 GCash</li>
        <li>💳 Maya</li>
        <li>🏦 Online Banking</li>
        <li>💵 Cash</li>
      </ul>
    </div>
  </div>
</div>
"""
    return page_html("Membership", body)


# ---------- RUN ----------
if __name__ == "__main__":
    app.run(debug=True)
