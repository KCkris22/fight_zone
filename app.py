from flask import Flask
app = Flask(__name__)

# ---------- BASE STYLE ----------
BASE = """
@import url('https://fonts.googleapis.com/css2?family=Anton&family=Rajdhani:wght@400;600;700&display=swap');
*{box-sizing:border-box;}
body{font-family:'Rajdhani',sans-serif;background:#000;color:#fff;margin:0;
     border-left:10px solid #c8102e;border-right:10px solid #c8102e;min-height:100vh;
     opacity:0;transition:opacity .5s ease-in-out;}
body.loaded{opacity:1;}
"""

# ---------- SITE STYLE ----------
STYLE = BASE + """
header{background:#c8102e;display:flex;justify-content:space-between;align-items:center;
       padding:15px 50px;box-shadow:0 2px 12px rgba(0,0,0,.5);}
header h1{font-family:'Anton',sans-serif;font-size:3rem;color:#000;text-shadow:2px 2px 0 #fff;
          letter-spacing:2px;transition:.3s;cursor:pointer;}
header h1:hover{transform:scale(1.05);text-shadow:0 0 15px #fff;}
nav{display:flex;gap:15px;}
nav a{background:#c8102e;color:#000;font-family:'Anton',sans-serif;text-transform:uppercase;
      padding:10px 20px;border-radius:10px;border:3px solid #000;text-decoration:none;
      box-shadow:0 4px 10px rgba(0,0,0,.5);transition:.3s;}
nav a:hover{transform:translateY(-5px);box-shadow:0 8px 20px rgba(200,16,46,.8);
            background:#ff1e38;}
.container{padding:40px;max-width:1200px;margin:auto;}
h2{color:#c8102e;font-family:'Anton',sans-serif;text-transform:uppercase;text-align:center;
   font-size:2.5rem;background:#111;padding:15px;border-radius:15px;border:4px solid #c8102e;
   box-shadow:0 0 20px rgba(200,16,46,.4);}
p{font-size:1.2rem;text-align:center;max-width:900px;margin:20px auto;line-height:1.6em;
  color:#f5f5f5;}
img.hero{width:80%;max-width:900px;display:block;margin:30px auto;border-radius:20px;
         box-shadow:0 0 25px rgba(200,16,46,.5);transition:.3s;}
img.hero:hover{transform:scale(1.03);box-shadow:0 0 35px rgba(200,16,46,.8);}
footer{background:#111;text-align:center;padding:20px;color:#888;margin-top:40px;
       border-top:5px solid #c8102e;}
.card-grid{display:flex;justify-content:center;flex-wrap:wrap;gap:30px;margin-top:40px;}
.card{background:#c8102e;border:4px solid #000;border-radius:20px;width:280px;padding:25px 20px;
      text-align:center;box-shadow:0 4px 15px rgba(0,0,0,0.6);transition:.3s;}
.card:hover{transform:translateY(-10px) scale(1.05);
            box-shadow:0 8px 25px rgba(200,16,46,.8);}
.card h3{font-family:'Anton',sans-serif;color:#000;font-size:1.3rem;margin-bottom:10px;}
.price{font-size:1.4rem;color:#fff;margin-bottom:10px;font-weight:bold;}
.join-btn{background:#000;color:#fff;font-family:'Anton',sans-serif;border:3px solid #fff;
          border-radius:10px;padding:10px 20px;cursor:pointer;transition:.3s;}
.join-btn:hover{background:#fff;color:#000;transform:scale(1.05);}

/* Modals */
.modal-bg,.bank-bg{position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,.85);
          display:flex;justify-content:center;align-items:center;visibility:hidden;
          opacity:0;transition:opacity .4s ease;}
.modal-bg.show,.bank-bg.show{visibility:visible;opacity:1;}
.modal,.bank-modal{background:#111;border:4px solid #c8102e;border-radius:15px;padding:30px;
       width:90%;max-width:420px;text-align:center;
       transform:scale(.7);transition:transform .3s ease;}
.modal.show,.bank-modal.show{transform:scale(1);}
.modal h3,.bank-modal h3{font-family:'Anton',sans-serif;color:#c8102e;margin-bottom:15px;}
.modal input,.modal select,.bank-modal input{width:100%;padding:10px;margin:8px 0;border-radius:8px;
                            border:none;font-size:1rem;background:#000;color:#fff;}
.modal button,.bank-modal button{background:#c8102e;color:#000;font-family:'Anton',sans-serif;border:3px solid #000;
              border-radius:10px;padding:10px 20px;margin-top:10px;cursor:pointer;
              transition:.3s;}
.modal button:hover,.bank-modal button:hover{background:#ff1e38;transform:scale(1.05);}
@keyframes fadeIn{from{opacity:0;}to{opacity:1;}}
@keyframes zoomIn{from{transform:scale(.75);}to{transform:scale(1);}}
"""

# ---------- SCRIPT ----------
SCRIPT = """
<script>
document.addEventListener("DOMContentLoaded",()=>{
  document.body.classList.add("loaded");
  document.querySelectorAll("a").forEach(link=>{
    link.addEventListener("click",e=>{
      if(link.hostname===location.hostname && link.getAttribute("href").startsWith("/")){
        e.preventDefault();
        document.body.classList.remove("loaded");
        setTimeout(()=>{window.location=link.href;},300);
      }
    });
  });
});

let currentPlan=null;
let userData={};

function openModal(plan,price){
  currentPlan={plan,price};
  document.getElementById('modalTitle').innerText=plan+" - ₱"+price;
  document.getElementById('modalForm').reset();
  document.querySelector('.modal-bg').classList.add('show');
  document.querySelector('.modal').classList.add('show');
}
function closeModal(){
  document.querySelector('.modal-bg').classList.remove('show');
  document.querySelector('.modal').classList.remove('show');
}
function openBankModal(){
  document.getElementById('cardNumber').value='';
  document.getElementById('cvv').value='';
  document.querySelector('.bank-bg').classList.add('show');
  document.querySelector('.bank-modal').classList.add('show');
}
function closeBankModal(){
  document.querySelector('.bank-bg').classList.remove('show');
  document.querySelector('.bank-modal').classList.remove('show');
}

function handlePayment(){
  const name=document.getElementById('name').value.trim();
  const phone=document.getElementById('phone').value.trim();
  const email=document.getElementById('email').value.trim();
  const method=document.getElementById('method').value;
  if(!name||!phone||!email||!method){
    alert('Please complete all fields.');
    return;
  }
  userData={name,phone,email,method};
  if(method==='Cash'){
    closeModal();
    showConfirmPopup(`
      <b>Thank you ${name}!</b><br><br>
      You chose <b>Cash</b> payment.<br>
      Balance to pay: ₱${currentPlan.price}<br><br>
      <b>Contact Information:</b><br>
      Name: ${name}<br>
      Phone: ${phone}<br>
      Email: ${email}`);
  } else {
    closeModal();
    setTimeout(()=>{openBankModal();},400);
  }
}

function submitBankPayment(){
  const card=document.getElementById('cardNumber').value.trim();
  const cvv=document.getElementById('cvv').value.trim();
  if(!/^[0-9]{16}$/.test(card)||!/^[0-9]{3}$/.test(cvv)){
    alert('Please enter a valid 16-digit card number and 3-digit CVV.');
    return;
  }
  closeBankModal();
  const first4=card.slice(0,4);
  showConfirmPopup(`
    <b>Payment confirmed!</b><br><br>
    You paid via <b>Bank</b>.<br>
    Plan: ${currentPlan.plan}<br>
    Card starts with: ${first4}**** **** ****<br><br>
    <b>Contact Information:</b><br>
    Name: ${userData.name}<br>
    Phone: ${userData.phone}<br>
    Email: ${userData.email}`);
}

function showConfirmPopup(message){
  const overlay=document.createElement('div');
  overlay.style.position='fixed';
  overlay.style.top='0';overlay.style.left='0';
  overlay.style.width='100%';overlay.style.height='100%';
  overlay.style.background='rgba(0,0,0,.85)';
  overlay.style.display='flex';
  overlay.style.justifyContent='center';
  overlay.style.alignItems='center';
  overlay.style.animation='fadeIn .4s forwards';
  overlay.innerHTML=`
    <div style="background:#111;border:4px solid #c8102e;border-radius:15px;
    padding:30px;width:90%;max-width:480px;text-align:justify;
    transform:scale(.7);animation:zoomIn .3s forwards;line-height:1.6em;">
      <h3 style="font-family:Anton,sans-serif;color:#c8102e;text-align:center;margin-bottom:15px;">
        Payment Summary
      </h3>
      <div style="font-size:1.1rem;color:#f2f2f2;">${message}</div>
      <div style="text-align:center;">
      <button onclick='this.parentElement.parentElement.parentElement.remove()'
        style="margin-top:18px;background:#c8102e;color:#000;font-family:Anton,sans-serif;
        border:3px solid #000;border-radius:10px;padding:10px 25px;cursor:pointer;">
        Close
      </button>
      </div>
    </div>`;
  document.body.appendChild(overlay);
}
</script>
"""

# ---------- HEADER / FOOTER ----------
HEADER = """
<header>
  <h1 onclick="window.location='/home'">FIGHT ZONE</h1>
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
<html lang='en'><head>
<meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1.0'>
<title>{title} – Fight Zone</title>
<style>{STYLE}</style></head>
<body>{HEADER}<div class='container'>{body}</div>{FOOTER}{SCRIPT}</body></html>"""

# ---------- ROUTES ----------
@app.route("/")
def start():
    return """
<!DOCTYPE html><html lang='en'><head>
<meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1.0'>
<title>Enter Fight Zone</title><style>""" + BASE + """
body{display:flex;flex-direction:column;justify-content:center;align-items:center;height:100vh;}
h1{font-family:'Anton',sans-serif;font-size:4rem;color:#c8102e;text-shadow:0 0 15px #c8102e;margin-bottom:30px;}
button{background:#c8102e;border:4px solid #000;color:#000;font-family:'Anton',sans-serif;
font-size:1.5rem;padding:20px 50px;border-radius:15px;cursor:pointer;
box-shadow:0 0 20px rgba(200,16,46,.6);transition:.3s;}
button:hover{transform:scale(1.1);box-shadow:0 0 40px rgba(200,16,46,.9);}
.fadeout{animation:fadeout .6s forwards;}
@keyframes fadeout{to{opacity:0;transform:scale(1.1);}}
</style></head>
<body><h1>WELCOME TO FIGHT ZONE</h1>
<button onclick="enterSite()">ENTER FIGHT ZONE</button>
<script>
document.body.classList.add('loaded');
function enterSite(){document.body.classList.add('fadeout');setTimeout(()=>{window.location='/home';},600);}
</script></body></html>"""

@app.route("/home")
def home():
    body = """
<h2>Welcome to Fight Zone</h2>
<p>Welcome to <strong>Fight Zone</strong> — the ultimate place to explore the power of boxing and fitness.</p>
<img src="/static/images/home_image.png" class="hero" alt="Home image">
<p>Boxing is more than a sport — it’s a mindset. Every punch brings you closer to your best self.</p>
"""
    return page_html("Home", body)

@app.route("/about")
def about():
    body = """
<h2>About Fight Zone</h2>
<p><strong>Fight Zone</strong> was founded by <strong>Cynric</strong> to inspire people through boxing.</p>
<img src="/static/images/about_image.png" class="hero" alt="About image">
<p>Boxing builds physical strength and mental toughness that extend beyond the ring.</p>
"""
    return page_html("About", body)

@app.route("/benefits")
def benefits():
    body = """
<h2>Benefits of Boxing</h2>
<p>Here are some key benefits of boxing training:</p>
<div class="card-grid">
  <div class="card"><h3>Cardio Health</h3><p>Improves endurance and heart strength.</p></div>
  <div class="card"><h3>Coordination</h3><p>Sharpens reflexes and balance.</p></div>
  <div class="card"><h3>Weight Control</h3><p>Burns fat and builds muscle.</p></div>
  <div class="card"><h3>Confidence</h3><p>Boosts discipline and self-esteem.</p></div>
  <div class="card"><h3>Focus</h3><p>Relieves stress and improves concentration.</p></div>
</div>
<div style='text-align:center;margin-top:60px;'>
<h3 style='color:#c8102e;font-family:Anton,sans-serif;font-size:1.6rem;'>DEUTERONOMY 20:4</h3>
<p>"For the Lord your God goes with you to fight for you and give you victory."</p></div>
"""
    return page_html("Benefits", body)

@app.route("/membership")
def membership():
    body = """
<h2>Membership Plans</h2>
<p>Choose your plan and join the Fight Zone community today!</p>
<div class="card-grid">
  <div class="card"><h3>Basic</h3><div class="price">₱500 / month</div>
       <p>Gym access + beginner classes.</p>
       <button class="join-btn" onclick="openModal('Basic Plan',500)">JOIN NOW</button></div>
  <div class="card"><h3>Pro</h3><div class="price">₱1 000 / month</div>
       <p>Includes trainer sessions (2×/mo).</p>
       <button class="join-btn" onclick="openModal('Pro Plan',1000)">JOIN NOW</button></div>
  <div class="card"><h3>Elite</h3><div class="price">₱2 000 / month</div>
       <p>VIP access + diet plan + sparring.</p>
       <button class="join-btn" onclick="openModal('Elite Plan',2000)">JOIN NOW</button></div>
</div>

<!-- Join Modal -->
<div class="modal-bg">
  <div class="modal">
    <h3 id="modalTitle">Join Fight Zone</h3>
    <form id="modalForm" onsubmit="event.preventDefault();handlePayment();">
      <input type="text" id="name" placeholder="Full Name">
      <input type="text" id="phone" placeholder="Phone Number">
      <input type="email" id="email" placeholder="Email Address">
      <select id="method">
        <option value="">Select Payment Method</option>
        <option value="Cash">Cash Payment</option>
        <option value="Bank">Online Bank Payment</option>
      </select>
      <button type="submit">Pay Now</button>
      <button type="button" onclick="closeModal()">Close</button>
    </form>
  </div>
</div>

<!-- Bank Modal -->
<div class="bank-bg">
  <div class="bank-modal">
    <h3>Bank Payment</h3>
    <input type="text" id="cardNumber" placeholder="Enter 16-digit Card Number">
    <input type="text" id="cvv" placeholder="Enter 3-digit CVV">
    <button onclick="submitBankPayment()">Submit Payment</button>
    <button onclick="closeBankModal()">Cancel</button>
  </div>
</div>
"""
    return page_html("Membership", body)

# ---------- RUN ----------
if __name__ == "__main__":
    app.run(debug=True)
