# 🍯 T-Pot Honeypot VPS 1 - Setup Guide

**VPS 1 Role:** T-Pot Honeypot + Real-time Data Sync to VPS 2

---

## 📋 Table of Contents

- [System Overview](#system-overview)
- [Prerequisites](#prerequisites)
- [Installation Steps](#installation-steps)
- [Configuration](#configuration)
- [Real-time Sync Setup](#real-time-sync-setup)
- [Automation with Crontab](#automation-with-crontab)
- [Monitoring](#monitoring)
- [Troubleshooting](#troubleshooting)

---

## 🏗️ System Overview

```
┌─────────────────────────────────────────┐
│         VPS 1 (T-Pot Honeypot)          │
│                                         │
│  ┌────────────────────────────────┐    │
│  │   T-Pot Honeypot Suite         │    │
│  │   - Dionaea (malware capture)  │    │
│  │   - Cowrie (SSH/Telnet)        │    │
│  │   - Suricata (IDS)             │    │
│  │   - 30+ honeypots              │    │
│  └────────────────────────────────┘    │
│              ↓                          │
│  ┌────────────────────────────────┐    │
│  │   Data Directory               │    │
│  │   ~/tpotce/data/               │    │
│  └────────────────────────────────┘    │
│              ↓                          │
│  ┌────────────────────────────────┐    │
│  │   Real-time Lsyncd	     	    │
│  │   → VPS 2 via rsync/SSH        │    │
│  └────────────────────────────────┘    │
│              ↓                          │
│  ┌────────────────────────────────┐    │
│  │   Logstash Dual Output         │    │
│  │   → Local ES + VPS 2 ES        │    │
│  └────────────────────────────────┘    │
└─────────────────────────────────────────┘
```

---

## ⚙️ Prerequisites

### System Requirements
- **OS:** Ubuntu 20.04+ / Debian 11+
- **RAM:** 8GB minimum (16GB recommended)
- **Disk:** 50GB minimum (100GB recommended)
- **Network:** Public IP address
- **Ports:** 64295 (T-Pot web interface)

### Software Requirements
- Docker & Docker Compose (installed by T-Pot)
- SSH access enabled
- Git (for cloning this repo)

---

---

###Precheck Logstash Config File
```bash
Test koneksi dari dalam container
docker exec -it tpot_logstash curl -v http://your-external-es:9200
```
###Cari tahu file sudah di mount
```bash
cat docker-compose.yml | grep logstash
  logstash:
    container_name: logstash
    image: ${TPOT_REPO}/logstash:${TPOT_VERSION}
     - $HOME/tpotce/docker/elk/logstash/dist/logstash.conf:/etc/logstash/logstash.conf  --> ini artinya sudah mount (sehinggaa perubahan bisa dilakukan di file config docker)
     - $HOME/tpotce/docker/elk/logstash/dist/http_input.conf:/etc/logstash/http_input.conf
```
###Kalau default belom ada mount : 
```bash
nano ~/tpotce/docker-compose.yml
```
###Cari bagian service logstash, tambahkan volumes:
- /home/user/tpotce/data:/data          # biasanya mount default yang sudah ada
- /home/user/tpotce/docker/elk/logstash/dist/logstash.conf:/etc/logstash/logstash.conf:ro   # tambahkan ini
- /home/user/tpotce/docker/elk/logstash/dist/http_input.conf:/etc/logstash/http_input.conf # tambahkan ini

###Periksa Mount Berhasil
```bash
docker inspect logstash | grep -A 20 '"Mounts"'

docker exec -it logstash cat /etc/logstash/logstash.conf
```

###Bandingkan dengan file host
```bash
cat ~/tpotce/docker/elk/logstash/dist/logstash.conf --> keduanya harus sama.
```
 ---
 

## 🔧 Configuration Logstash 

### Configure Logstash Dual Output

**Location:** `~/tpotce/elk/logstash/dist/logstash.conf`

Add this output section to existing Logstash config:

```ruby
output {
  # Output 1: Local Elasticsearch (T-Pot default)
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    index => "logstash-%{+YYYY.MM.dd}"
  }
  
  # Output 2: External Elasticsearch (VPS 2)
  elasticsearch {
    hosts => ["http://VPS2_IP:9200"]  # Replace with VPS 2 IP
    index => "tpot_data-%{+YYYY.MM.dd}"
  }
}
```

**Restart Logstash:**

```bash
cd ~/tpotce
docker compose up -d logstash
```

---

**Cek Index di ES VPS-2**
```bash
http://IP_VPS2:9200/_cat/indices?v
```

---

## Konfigurasi Lsyncd
Install system packages
```bash
sudo apt update
sudo apt install lsyncd
```
### Step 2: Configure Sync Script
```bash
sudo nano /etc/lsyncd/lsyncd.conf.lua
(masukkan script lsyncd)
```
### Konfig Direktori
```bash
sudo mkdir -p /var/log/lsyncd
sudo touch /var/log/lsyncd/lsyncd.log
sudo touch /var/log/lsyncd/lsyncd.status
sudo chown -R root:root /var/log/lsyncd
```
### Step 3: Configure SSH Key for Passwordless Login
```bash
# Generate SSH key (if not exists)
ssh-keygen -t rsa -b 4096 -N "" -f ~/.ssh/id_rsa

# Copy public key to VPS 2
ssh-copy-id USERNAME@VPS2_IP

# Test connection
ssh USERNAME@VPS2_IP "echo 'SSH OK'"
# Should login without password and return 'SSH OK'
```

### Jalankan Lsyncd
```bash
sudo systemctl enable lsyncd
sudo systemctl start lsyncd
```
## 🔄 Real-time Sync Setup

### Manual Test
```bash
rsync -avz --progress \
  -e "ssh -i /home/user/.ssh/id_rsa" \
  /home/user/tpotce/data/ \
  user@IP:/home/user/honeypot_logs/tpot_data/
```

###Verification
# Check lsyncd is running
```bash
sudo systemctl status lsyncd | grep Active

# Check logs for sync activity
sudo tail -20 /var/log/lsyncd/lsyncd.log
```
---

## 📊 Monitoring

### Check Sync Status

```bash
# View sync logs
tail -f /var/log/lsyncd/lsyncd.log

# Check if sync is running
sudo systemctl status lsyncd

it should Active and Normal. 

systemd[1]: Starting LSB: lsyncd daemon init script...
lsyncd[705]:  * Starting synchronization daemon lsyncd
lsyncd[758]: 13:45:49 Normal: --- Startup, daemonizing ---
lsyncd[705]:    ...done.
systemd[1]: Started LSB: lsyncd daemon init script.
```

# Check data synced to VPS 2
```bash
ssh USERNAME@VPS2_IP "du -sh ~/honeypot_logs/tpot_data/"
```

---

### Check Logstash Dual Output

```bash
# Check Logstash logs
docker logs logstash | grep -i output

# Test local ES
curl http://localhost:9200/_cat/indices?v

# Test VPS 2 ES
curl http://VPS2_IP:9200/_cat/indices?v
```

---

## 🐛 Troubleshooting

### Issue 1: Host Key Verification Failed
Gejala : 
Host key verification failed.
rsync: connection unexpectedly closed (0 bytes received so far) [sender]
rsync error: unexplained error (code 255)

Penyebab : SSH Host key gaada di root's known_host

**Fix:**

```bash
# Add host key for root
ssh-keyscan -H IP_VPS_Target | sudo tee -a /root/.ssh/known_hosts

# Test SSH as root
sudo ssh user@ip "echo OK"
# Should print: OK ✅

# Restart lsyncd
sudo systemctl restart lsyncd
```
---

### Issue 2: Permission Denied (Publickey)
Gejala : 
user@IP: Permission denied (publickey).

Penyebab :
Root doesn't have SSH key or key not authorized on VPS 2.

**Fix:**

```bash
sudo ls -la /root/.ssh/id_rsa

# If not exists, copy from user or create new:
sudo mkdir -p /root/.ssh
sudo cp ~/.ssh/id_rsa* /root/.ssh/
sudo chown -R root:root /root/.ssh
sudo chmod 600 /root/.ssh/id_rsa

# 2. Copy public key to VPS 2
sudo ssh-copy-id -i /root/.ssh/id_rsa.pub user@IP

# 3. Test connection
sudo ssh user@IP "echo OK"

# 4. Restart lsyncd
sudo systemctl restart lsyncd
```

---

### Issue 3: Real-time sync not working

**Check:**

```bash
# 1. Check if lsyncd is actually running
ps aux | grep lsyncd | grep -v grep

# 2. Check recent activity in logs
sudo tail -50 /var/log/lsyncd/lsyncd.log

# Look for:
# "Rsyncing list" ✅ - Good, syncing
# "Normal: Finished a list" ✅ - Good
# No recent entries ❌ - Not detecting changes
# Errors ❌ - Check specific error
```
**Fix:**
```bash 
sudo systemctl restart lsyncd

# Create test file to trigger sync
sudo touch /home/user/tpotce/data/test_sync_$(date +%s).txt

# Wait 10 seconds
sleep 10

# Check logs
sudo tail -20 /var/log/lsyncd/lsyncd.log
# Should show sync activity ✅

# Check on VPS 2
ssh emanueldananjayakusu@34.50.109.118 "ls -la ~/honeypot_logs/tpot_data/test_sync*"
```

---
