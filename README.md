# SRAM PUF on ESP32: keys from the silicon, encrypted data over WiFi

An ESP32 derives its cryptographic keys from the manufacturing variations of its own SRAM instead of storing them in memory. At every power-up the key is **rebuilt from the chip** and used to authenticate to a server and send it encrypted temperature and humidity readings from a DHT11 sensor.

No key is stored in flash: dumping the whole memory of the board yields nothing usable.

---

## 1. Overview

| | |
|---|---|
| **Hardware** | ESP32 (tested on rev. v3.1); DHT11 sensor and SSD1306 display optional |
| **Firmware** | ESP-IDF v6.1, C, cryptography through PSA Crypto (mbedTLS 4) |
| **Host** | Python 3: enrollment, server, demo |
| **PUF** | 1020 stable SRAM cells, BCH(255,179,10) over 4 blocks |
| **Keys** | K_master from SHA-256; K_auth for HMAC-SHA256; K_enc to derive a per-session AES-256-GCM key |
| **Network** | WiFi WPA2 + TCP, line-based text protocol |

---

## 2. Step-by-step guide

### 2.1 Requirements

- an ESP32 board connected over USB;
- [ESP-IDF v6.1](https://docs.espressif.com/projects/esp-idf/) installed (`get_idf` or `. $IDF_PATH/export.sh`);
- Python 3 with a virtual environment for the host scripts;
- optional: DHT11 on **GPIO4**, SSD1306 128x64 display on I2C (**SDA 21, SCL 22**, address 0x3C).

Without a sensor or a display the project still builds: CMake automatically picks `sensor_fake.c` (synthetic readings) and `display_none.c` (no screen).

### 2.2 Layout

```
main/                 firmware
  boot.c              main program: key, network, protocol, data
  puf.c               extracts the cells selected by the mask
  fuzzy.c             BCH decoder (syndromes, Berlekamp-Massey, Chien search)
  crypto.c            SHA-256, HKDF, HMAC, AES-GCM through PSA
  net.c               WiFi + line-based TCP
  sensor_*.c          DHT11 or synthetic readings
  display_*.c         SSD1306 or nothing
  puf_region.h        address and size of the SRAM region
  pk_prov.h           public key that verifies the helper data
  wifi_secrets.example.h

host/                 scripts run on the computer
  analyze.py          PUF statistics on the dumps (uniformity, intra-distance)
  mask.py             majority voting and selection of the stable cells
  fuzzy.py            BCH and fuzzy extractor (reference for the C code)
  helperdata.py       helper data format and ECDSA signature
  enroll.py           enrollment: mask, helper data, signature
  reproduce.py        offline test of the key reconstruction
  server_keys.py      derives the server-side keys
  server.py           TCP server: authentication and decryption
  flash_check.py      demo: looks for the keys in a flash dump
  nvs.csv             NVS partition holding the helper data
  nvs_tampered.csv    same, with altered helper data (demo)

data/fixed/           helper data (hd.bin), NVS partition, expected key id
keys/                 server and provisioner keys (never committed)
```

### 2.3 Python environment

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install cryptography
```

If you use conda, run `conda deactivate` before `get_idf`: it interferes with the ESP-IDF Python. Keep **two terminals**: one with the venv for the host scripts, one with `get_idf` for the firmware.

### 2.4 Enrollment (once per board)

Enrollment measures the SRAM of the board and produces the **helper data**, the public value that allows the key to be rebuilt. It is done once and never repeated: two different helper data for the same SRAM would compromise it (see 3.3).

1. Collect many power-up readings of the SRAM region.
2. `analyze.py` computes the statistics: uniformity, intra-chip distance, stable cells.
3. `enroll.py` selects the stable cells by majority voting, computes the helper data, signs it with the provisioner private key and writes `data/fixed/hd.bin`, `main/pk_prov.h` and the expected key id.
4. The helper data is written to the NVS partition of the board (`nvs.csv`).
5. `reproduce.py` checks offline that the key is rebuilt from every collected reading.

For this board enrollment is already done: `data/fixed/` holds the signed helper data.

### 2.5 WiFi configuration

```bash
cp main/wifi_secrets.example.h main/wifi_secrets.h
```

Then set SSID, password and the server IP in `main/wifi_secrets.h` (on macOS: `ipconfig getifaddr en0`). The file is git-ignored. The ESP32 only sees **2.4 GHz** networks.

### 2.6 Server keys

The server needs K_auth and K_enc. `server_keys.py` rebuilds them on the computer (trusted environment) and stores them in `keys/server_keys.json`:

```bash
source .venv/bin/activate
python3 host/server_keys.py
```

### 2.7 Run

Terminal 1, server (venv active):

```bash
python3 host/server.py
```

Terminal 2, board (`get_idf`):

```bash
idf.py -p /dev/cu.usbserial-0001 flash monitor
```

Expected output on the board:

```
Signature OK
All checks passed.
Key rebuilt.
WiFi: connected, IP 192.168.1.24
TCP: connected to 192.168.1.6:5555

Authentication OK: device and server share K_auth.
Session key derived.
```

And on the server:

```
[192.168.1.24:61329] device AUTHENTICATED
[192.168.1.24:61329] seq 1: temperature 24.8 C, humidity 52 %
```

The readings also appear on the display.

**After resetting or re-flashing the board, restart the server.** A board reset does not close the old TCP connection, and the server would keep waiting on it.

### 2.8 Demo: no key in flash

Read the whole flash as an attacker with a USB cable would, then search it for the keys:

```bash
# terminal with get_idf, monitor closed
python -m esptool --port /dev/cu.usbserial-0001 read-flash 0 ALL flash_dump.bin

# terminal with the venv
python3 host/flash_check.py flash_dump.bin
rm flash_dump.bin          # it contains the WiFi password
```

Result on the test board:

```
SECRETS (must NOT be in the flash)
  K_master   not found
  K_auth     not found
  K_enc      not found

CONTROLS (must be in the flash: they prove the search works)
  helper data (first 64 B)   found  @ 0x009080
  helper data signature      found  @ 0x009515
  WiFi password              found  @ 0x016460
```

The WiFi password, stored the classic way, is readable with one command. The PUF keys are not, because they are never written.

---

## 3. The idea

### 3.1 The problem: where do you keep a key?

An IoT device that encrypts data needs a key. Usually it is written to flash, but anyone holding the board can read it back with a cable and `esptool`. Protecting it requires dedicated hardware (secure element, flash encryption with eFuses), which adds cost and complexity.

A **PUF** (Physically Unclonable Function) changes the question: the key is not stored, it is **measured**. It is a physical property of the chip, different for every device and not reproducible even by the manufacturer.

### 3.2 Why SRAM

Each SRAM cell is made of two cross-coupled inverters. At power-up the cell settles to 0 or 1 depending on tiny transistor mismatches left by manufacturing. Most cells always prefer the same value, but the pattern differs from chip to chip.

The SRAM power-up state is therefore a **fingerprint of the chip**. On the test board, over a 1024-byte region:

| Metric | Value | Meaning |
|---|---|---|
| Uniformity | 49.5% | zeros and ones almost balanced: no bias |
| Intra-chip distance | ~6% | bits that change between two power-ups of the same board |
| Stable cells | 90.5% | cells that never changed across the collected readings |

Uniqueness across chips (inter-chip distance around 50%) is a known result for SRAM PUFs and is assumed
