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

## 📥 Installation Steps

### Step 1: Clone This Repository

```bash
# On VPS 1
cd ~
git clone https://github.com/YOUR_USERNAME/honeypot-tpot-vps1.git
cd honeypot-tpot-vps1
```

---

** Precheck Logstash Config File
Test koneksi dari dalam container
docker exec -it tpot_logstash curl -v http://your-external-es:9200

** Cari tahu file sudah di mount
--> cat docker-compose.yml | grep logstash
  logstash:
    container_name: logstash
    image: ${TPOT_REPO}/logstash:${TPOT_VERSION}
     - $HOME/tpotce/docker/elk/logstash/dist/logstash.conf:/etc/logstash/logstash.conf  --> ini artinya sudah mount (sehinggaa perubahan bisa dilakukan di file config docker)
     - $HOME/tpotce/docker/elk/logstash/dist/http_input.conf:/etc/logstash/http_input.conf

** Kalau default belom ada mount : 
nano ~/tpotce/docker-compose.yml

Cari bagian service logstash, tambahkan volumes:
- /home/user/tpotce/data:/data          # biasanya mount default yang sudah ada
- /home/user/tpotce/docker/elk/logstash/dist/logstash.conf:/etc/logstash/logstash.conf:ro   # tambahkan ini
- /home/user/tpotce/docker/elk/logstash/dist/http_input.conf:/etc/logstash/http_input.conf # tambahkan ini

** Periksa Mount Berhasil
docker inspect logstash | grep -A 20 '"Mounts"'

docker exec -it logstash cat /etc/logstash/logstash.conf

** Bandingkan dengan file host
cat ~/tpotce/docker/elk/logstash/dist/logstash.conf --> keduanya harus sama.
 
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
http://IP_VPS2:9200/_cat/indices?v



## Konfigurasi Lsyncd
Install system packages
sudo apt update
sudo apt install lsyncd

## Step 2: Configure Sync Script

sudo nano /etc/lsyncd/lsyncd.conf.lua
(masukkan script lsyncd)

# Konfig Direktori
sudo mkdir -p /var/log/lsyncd
sudo touch /var/log/lsyncd/lsyncd.log
sudo touch /var/log/lsyncd/lsyncd.status
sudo chown -R root:root /var/log/lsyncd

## Step 3: Configure SSH Key for Passwordless Login

```bash
# Generate SSH key (if not exists)
ssh-keygen -t rsa -b 4096 -N "" -f ~/.ssh/id_rsa

# Copy public key to VPS 2
ssh-copy-id USERNAME@VPS2_IP

# Test connection
ssh USERNAME@VPS2_IP "echo 'SSH OK'"
# Should login without password ✅
```

## Jalankan Lsyncd
sudo systemctl enable lsyncd
sudo systemctl start lsyncd

## 🔄 Real-time Sync Setup

### Manual Test

rsync -avz --progress \
  -e "ssh -i /home/user/.ssh/id_rsa" \
  /home/user/tpotce/data/ \
  user@IP:/home/user/honeypot_logs/tpot_data/

**Verification**
# Check lsyncd is running
sudo systemctl status lsyncd | grep Active

# Check logs for sync activity
sudo tail -20 /var/log/lsyncd/lsyncd.log

---

## 📊 Monitoring

### Check Sync Status

```bash
# View sync logs
tail -f /var/log/lsyncd/lsyncd.log

# Check if sync is running
sudo systemctl status lsyncd

it should Active and Normal. 
```
systemd[1]: Starting LSB: lsyncd daemon init script...
lsyncd[705]:  * Starting synchronization daemon lsyncd
lsyncd[758]: 13:45:49 Normal: --- Startup, daemonizing ---
lsyncd[705]:    ...done.
systemd[1]: Started LSB: lsyncd daemon init script.
```

# Check data synced to VPS 2
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

### Issue 1: Sync Script Not Running

**Check:**

```bash
# Is script executable?
ls -la sync_to_vps2.sh

# Fix permissions
chmod +x sync_to_vps2.sh

# Test SSH connection
ssh USERNAME@VPS2_IP
```

---

### Issue 2: Permission Denied on Log File

**Fix:**

```bash
# Create log file with correct permissions
touch ~/honeypot-sync.log
chmod 644 ~/honeypot-sync.log
```

---

### Issue 3: Logstash Dual Output Not Working

**Check:**

```bash
# View Logstash config
docker exec logstash cat /usr/share/logstash/pipeline/logstash.conf

# Check Logstash errors
docker logs logstash | grep -i error

# Restart Logstash
cd ~/tpotce
docker-compose restart logstash
```

---

### Issue 4: Data Not Syncing

**Check:**

```bash
# Is inotify watching correctly?
ps aux | grep inotifywait

# Check source directory exists
ls -la /home/YOUR_USER/tpotce/data/

# Check network connectivity
ping VPS2_IP

# Check SSH key
ssh -i ~/.ssh/id_rsa USERNAME@VPS2_IP
```
