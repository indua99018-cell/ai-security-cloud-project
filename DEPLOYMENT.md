# Deploying to a REAL Free Cloud — Step by Step

Your project now uses **genuine system metrics** (via `psutil`) instead of
simulated numbers — CPU and memory readings are real, live data from
whatever machine runs it. Once deployed to an actual cloud server, those
numbers reflect that real server. This guide gets it there, for free.

Two options, pick based on what you need:

| | **Option A: Render** | **Option B: Oracle Cloud Always Free** |
|---|---|---|
| Setup time | ~10 minutes | ~30–45 minutes |
| "Real cloud" feel | Managed platform (still real hosting) | Actual VM you SSH into — closest to "real cloud" |
| Free tier limit | Sleeps after 15 min idle, wakes on request | **Always free, forever**, no sleep |
| Needs credit card | No | Yes, for identity verification only (never charged on free tier) |
| Best for | Quick demo link for your review | A genuinely always-on real cloud server |

---

## Option A — Render.com (fastest)

1. **Push your project to GitHub** (create a new repo, upload the whole `AI_Security_AutoScaling` folder).
2. Go to **render.com** → sign up free (GitHub login works) → **New → Web Service**.
3. Connect your GitHub repo.
4. Fill in:
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `gunicorn app:app --workers 1 --threads 4 --timeout 120`
   - **Instance Type:** Free
5. Click **Create Web Service**. Wait ~2–3 minutes for the first build.
6. You'll get a live public URL like `https://your-project.onrender.com` — that's your real, live dashboard.

**Note:** On the free tier, Render puts the app to sleep after 15 minutes with no traffic, and it takes ~30 seconds to wake up on the next visit. Open it a minute before your review starts so it's already awake.

---

## Option B — Oracle Cloud Always Free (a genuine real VM)

This gives you an actual Linux server that's free **forever**, not a trial — the real deal for a "real cloud" claim.

1. Go to **cloud.oracle.com** → **Start for free** → sign up (needs a card for identity verification only; the Always Free tier never charges it).
2. Once in the console: **Compute → Instances → Create Instance**.
3. Choose:
   - **Image:** Canonical Ubuntu 22.04
   - **Shape:** click "Change shape" → select **VM.Standard.E2.1.Micro** (this is the Always Free shape) — or an Ampere A1 shape if available, also free.
4. Under **Add SSH keys**, either generate a new key pair and download it, or paste your own public key.
5. Click **Create**. Wait ~1 minute for it to provision, then copy its **Public IP**.
6. **Open the firewall port** (important — Oracle blocks ports by default):
   - In the instance details, click your **Subnet** → **Security Lists** → default security list → **Add Ingress Rule**
   - Source CIDR: `0.0.0.0/0`, Destination Port: `5000` (or `80` if you set up Nginx later)
7. **SSH into your new real server:**
   ```bash
   ssh -i /path/to/your-key.pem ubuntu@<your-public-ip>
   ```
8. **On the server**, install Python and your project:
   ```bash
   sudo apt update && sudo apt install -y python3-pip python3-venv
   git clone <your-github-repo-url>
   cd AI_Security_AutoScaling
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   python3 train_model.py
   ```
9. **Also open the OS-level firewall** (Ubuntu's own, separate from Oracle's):
   ```bash
   sudo iptables -I INPUT -p tcp --dport 5000 -j ACCEPT
   sudo netfilter-persistent save
   ```
10. **Run it** (keep it running after you disconnect using `nohup`):
    ```bash
    nohup python3 app.py > app.log 2>&1 &
    ```
11. Visit `http://<your-public-ip>:5000` in your browser — that's a real, always-on cloud VM serving your dashboard with real CPU/memory from that actual server.

**Tip for the review:** SSH in and run `htop` in one terminal while your dashboard is open in a browser — you can show the panel your dashboard's CPU number matching the real server's CPU number live. That's a strong "this is really real" moment.

---

## Using the "Run Load Test" buttons

Once deployed (either option), your dashboard has two buttons: **Run DDoS Load Test** and **Run Brute-Force Test**. These don't fake numbers — they genuinely spike that server's real CPU for ~15 seconds and inject realistic traffic-shaped signals, so you can show your AI detecting something real happening live, safely, without ever sending traffic to an external target.

## What's real vs. what's still simulated — be upfront about this

If a reviewer asks "is this all real," the honest answer:
- **CPU, memory** — 100% real, live from the server.
- **Request rate, errors, login failures** — real if there's real traffic; the load-test button generates real (self-triggered) traffic against your own server for demo purposes.
- **The AI model, detection logic, and scaling decisions** — 100% real, same code either way.
- **What's NOT done:** actual multi-VM auto-scaling (spinning up/down real additional servers via a cloud provider's API) — the `AutoScaler` module tracks a scaling *decision* and instance *count*, but doesn't yet call Oracle/AWS APIs to actually provision new VMs. That's a natural "future work" point to mention if asked — technically straightforward to add (the OCI/AWS SDK call would replace the `instances += 1` line), but out of scope for this review stage.
