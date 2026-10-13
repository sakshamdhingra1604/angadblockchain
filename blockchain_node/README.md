# Angad Blockchain Node - Docker & Manual Cloudflare Tunnel Setup

This directory contains the Docker configuration for running the **Angad Blockchain Node** with persistent block storage, plus the configuration for running your **Cloudflare Tunnel (`cloudflared`)** manually on the host.

---

## 📁 Architecture Overview

```
[ Internet / Mobile App / Web Clients ]
                  │ (HTTPS)
                  ▼
         [ Cloudflare Edge ]
                  │ (Encrypted Tunnel)
                  ▼
  [ cloudflared (running on your host) ]
                  │ (Routes to http://127.0.0.1:8080)
                  ▼
 [ Docker Container: angad-blockchain-node ]
                  │
          (Persistent Volume)
                  ▼
          /app/data/chain.json
```

---

## 🚀 Step 1: Start the Dockerized Blockchain Node

Start the blockchain node with persistent storage:

```bash
docker compose up -d --build
```

- Node runs on: `http://localhost:8080` (or `http://127.0.0.1:8080`)
- Persistent chain data is stored in the Docker volume `blockchain_data` (`/app/data/chain.json`).
- View logs:
  ```bash
  docker compose logs -f
  ```

---

## 🌐 Step 2: Run Cloudflare Tunnel Manually

Choose **Option A** (Quick Token method) or **Option B** (Config file method):

### Option A: Quick Token Run (Zero Trust Dashboard)
If you created your tunnel in the Cloudflare Dashboard (**Zero Trust > Networks > Tunnels**), simply run:

```bash
cloudflared tunnel run --token <YOUR_TUNNEL_TOKEN>
```

In the Cloudflare Dashboard, set the **Public Hostname**:
- **Domain:** `node.yourdomain.com`
- **Service:** `HTTP` -> `127.0.0.1:8080`

---

### Option B: Using `cloudflared` CLI & Config File

1. **Login & create tunnel:**
   ```bash
   cloudflared tunnel login
   cloudflared tunnel create angad-node
   ```

2. **Route your DNS subdomain to the tunnel:**
   ```bash
   cloudflared tunnel route dns angad-node node.yourdomain.com
   ```

3. **Configure `~/.cloudflared/config.yml`:**
   Copy the sample from [`cloudflared/config.yml`](cloudflared/config.yml) to `~/.cloudflared/config.yml` and replace `YOUR_TUNNEL_UUID` with your actual tunnel UUID:
   ```yaml
   tunnel: <TUNNEL_UUID>
   credentials-file: /home/sonu/.cloudflared/<TUNNEL_UUID>.json

   ingress:
     - hostname: node.yourdomain.com
       service: http://127.0.0.1:8080
     - service: http_status:404
   ```

4. **Start the tunnel:**
   ```bash
   cloudflared tunnel run angad-node
   ```

*(Optional)* Run `cloudflared` as a system service in the background:
```bash
sudo cloudflared service install
sudo systemctl start cloudflared
```

---

## 🔍 Verification & Endpoints

Test that everything is reachable:

- **Local Web Dashboard & Explorer:**
  Open in browser: `http://localhost:8080/`

- **Local API Endpoints:**
  ```bash
  curl http://localhost:8080/health
  curl http://localhost:8080/stats
  curl http://localhost:8080/chain
  curl http://localhost:8080/validate
  ```

- **Via Cloudflare Tunnel:**
  ```bash
  curl https://node.yourdomain.com/health
  curl https://node.yourdomain.com/stats
  curl https://node.yourdomain.com/chain
  ```
