# Intrusion Monitor

**A free, no-install early-warning tool for Windows. It watches your PC and warns you — in plain English — the moment something starts probing your machine or your PC contacts a known-bad address on the internet. It shows you who is behind the connection, gives you a one-click button to cut it off, and keeps a tamper-proof record you can hand to your ISP, the attacker's network provider or the police.**

Built for ordinary PC users, not just security professionals. No installer, no background service you have to trust, no account. It is a single script you double-click, and you can close it any time.

---

## What it does

When it's running, Intrusion Monitor quietly keeps an eye on your own computer and raises a big, easy-to-read alert if it sees any of these:

- **Someone scanning your PC** — a tell-tale burst of probes against lots of your ports at once, the way automated attack tools start.
- **Your PC contacting a known-bad address** — connections or web lookups to internet infrastructure linked to the ARTEX automated-attack toolkit.
- **A tripwire being touched** — it quietly puts a tempting-looking decoy folder in place (and, if you switch it on, a decoy network share); if anything pokes at it, you hear about it immediately. Nothing legitimate ever touches that folder, so an alert there is a real signal.
- **New devices appearing** on your local network (shown as information, not an alarm), with their hardware (MAC) address and maker.
- **Every incoming connection attempt, counted per address** — who has tried to connect to your PC, how many times, whether they were refused or let in, every port number they tried, and which program on your PC they were aiming at. Press **Connections** to see the table.

Each address is labelled by where it comes from, so your own programs never set off an alarm:

| From | What it is | What happens |
|------|-----------|--------------|
| **This PC** | 127.0.0.1 and your PC's own addresses — programs on your computer talking to each other | Listed in grey. **Never** alarms. |
| **Home network** | 192.168.x.x, 10.x.x.x and similar — your router, phones, TV, other PCs | Listed with device name and maker. A scan or repeated refusals gives an amber warning only. |
| **Internet** | Everything else | Can raise the red alarm and the Disconnect & Block pop-up. |

When the alert involves an internet address, the pop-up tells you **where it's coming from** — country, internet provider, who the address is registered to, and the **abuse contact** to report it to — and gives you a **Disconnect & Block** button that slams the door on that address at the Windows Firewall.

---

## Evidence you can rely on

Everything Intrusion Monitor sees is written down as it happens, in a form that shows if anyone has changed it afterwards.

**What gets recorded for every attempt**

- The time, in both **UTC** (the international standard) and your **local time**.
- The attacker's address and port, and where it's from (this PC / home network / internet).
- Which of your PC's addresses and network adapters it hit, the port, and **which program on your PC owned that port**.
- The exact line Windows Firewall wrote, word for word.
- For home-network devices: the **MAC address** (the device's hardware ID) and its **maker**. *(Internet traffic always arrives via your router, so a MAC address is only meaningful on your own network.)*

**Who and where — looked up automatically for every new address**

- **Reverse DNS name** (the address's internet name, if it has one).
- **Registry record** (RDAP/WHOIS): who the network is registered to, its address range, and the **abuse contact** — the email address that network's owner publishes for reporting attacks.
- Country, internet provider and network number (ASN).
- **Traceroute**: when an internet address sets off a red alert, Intrusion Monitor automatically records the route across the internet to it. There's also a **Trace route** button.

These are ordinary, legal lookups — the same public "who are you?" questions any network engineer asks. Intrusion Monitor never attacks back.

**Making the times trustworthy**

- Once an hour it checks your PC's clock against internet time and records the difference, along with your public internet address.
- It records which network you were on (adapter, addresses, router and its MAC address, Wi-Fi name), and records it again whenever that changes.

**Tamper-evident**

- Every record has a sequence number and a SHA-256 fingerprint that includes the fingerprint of the record before it — a chain. **Change, delete or reorder any record and the chain breaks.**
- At the end of each day the day's file is **sealed**: its fingerprint is written to a separate seal file and to `Seals.txt`, and the file is made read-only.
- **Verify logs** (in the Connections window) checks the whole chain and tells you, line by line, if anything has been altered or removed.

**Handing it over**

Press **Export evidence** in the Connections window. It builds one zip file containing:

- the evidence journal and seals, the spreadsheets, and a copy of the Windows Firewall log;
- **Incident_Summary.txt** — a plain-English summary: each attacker, when, how often, which ports, who they're registered to, the abuse contact, traceroutes, your clock accuracy and network;
- **Verification.txt** — the result of checking the chain at that moment;
- **MANIFEST.txt** — the fingerprint of every file in the pack;
- a copy of the exact version of Intrusion Monitor that made the record.

The zip's own fingerprint is copied to your clipboard and saved next to it. **Write it down or email it to yourself** — it proves the pack hasn't been changed since you made it.

> Registry and location details show who an address is *registered to* — the network responsible — not necessarily the person at the keyboard. That's exactly what an ISP, abuse desk or the police need to follow it up.

---

## Download and install

You don't really "install" it — you just download it and run it.

1. On this page, click **Releases** (on the right), open the latest release, and click **Source code (zip)** under **Assets**. *(Or click the green **Code** button, then **Download ZIP**.)*
2. Find the downloaded ZIP (usually in your **Downloads** folder), **right-click it**, and choose **Extract All…**, then **Extract**.
3. Open the extracted **IntrusionMonitor** folder (its name may end in the version number, e.g. `IntrusionMonitor-2.0`).
4. Double-click **`IntrusionMonitor.vbs`**. It starts silently in the background — no black command window — and sits minimised until it sees something.
5. The first time, Windows may show a blue **"Windows protected your PC"** box, because the tool isn't signed by a big company. Click **More info**, then **Run anyway**. *(Normal for free, open tools.)* Some antivirus programs may also query it, because it reads the firewall log and can add firewall rules — the same things that make it useful. You can read every line of it in `IntrusionMonitor.ps1`.
6. That's it — it's watching. The window only pops open when there's an alert to show you; otherwise it stays out of your way.

To stop it, open the window (it pops up on an alert, or click its taskbar icon) and press **Stop**.

### Turning on blocking and full evidence (recommended)

Blocking attackers and reading the Windows Firewall log need Administrator rights, so they're off until you ask. In the monitor window, press **Elevate** and answer **Yes** to the Windows prompt. It reopens in full mode, adding the **Disconnect & Block** button, inbound port-scan detection, counting of *refused* attempts (where scans show up), and the firewall log in evidence packs. Your own router and PC are never blockable, so you can't cut yourself off.

### If your antivirus has its own firewall

Some security suites (Kaspersky, Norton, ESET, Bitdefender and others) replace Windows Firewall with their own. Intrusion Monitor spots this automatically and tells you. In that case:

- Windows Firewall's log stays empty, so Intrusion Monitor counts **live incoming connections** instead. Attempts your security suite *refused* are recorded in that product's own reports, not here.
- The **Block** button still adds Windows Firewall rules, but your suite may ignore them, so Intrusion Monitor will remind you to block the address in your suite as well.

---

## Understanding the alerts

| Colour | Meaning |
|--------|---------|
| **Red (HIGH)** | Something that deserves your attention now — a scan, a known-bad connection, or a tripwire hit. |
| **Orange (MED)** | Worth noticing — a suspicious name lookup, a home-network device probing you, or your PC's clock being wrong. |
| **Amber (INFO)** | Just information — the tool starting, a new device on your network, a traceroute saved. |

A red alert with an internet address will pop its own window showing who's behind it and a **Disconnect & Block** button.

---

## The Connections window

| Button | What it does |
|--------|--------------|
| **Refresh** | Updates the table. |
| **Look up** | Looks up who the selected address belongs to (done automatically too). |
| **Trace route** | Records the route across the internet to the selected address. |
| **Block** | Blocks the selected address at the firewall (needs Elevate). |
| **Export evidence** | Builds the evidence pack zip and opens its folder. |
| **Verify logs** | Checks that nothing in the evidence journal has been altered. |
| **Open logs** | Opens the logs folder. |

### The decoy network share (optional)

When elevated, Intrusion Monitor can also publish a decoy network share called **Backups**. Nothing legitimate ever opens it, so anything that does is almost certainly scanning your network. It's **off by default**, because a share makes your PC visible to everyone on the same network — fine at home, not what you want on café or hotel Wi-Fi. To switch it on, change `ShareDecoyEnabled = $false` to `$true` near the top of `IntrusionMonitor.ps1`.

---

## Privacy — what leaves your PC

Intrusion Monitor sends nothing about **you** anywhere. But to find out who is probing you, it looks up the **address of whoever connected to you** with these public services:

| Service | What it's sent | Why |
|---------|----------------|-----|
| ip-api.com | The connecting address | Country, internet provider, network number. *Plain HTTP (not encrypted); free for personal, non-commercial use.* |
| rdap.org (forwards to the official internet registries) | The connecting address | Who the address is registered to and its abuse contact. |
| Your normal DNS | The connecting address | Its reverse DNS name. |
| google.com | Nothing but a request for the time | Checking your PC clock. |
| api.ipify.org | Nothing | Recording your own public address. |
| IEEE / Wireshark | Nothing | Downloading the list of network-device makers (twice a year). |

A traceroute sends ordinary network test packets towards the connecting address. All of this can be switched off in the settings at the top of `IntrusionMonitor.ps1` (`AutoIdentify`, `AutoTraceroute`, `ClockCheckMinutes = 0`, `IpLookupEnabled`).

---

## What it can't do (so you're not misled)

- It watches **your own PC**. On a normal home or office network it **cannot** see attacks against your neighbour's machine — that traffic never reaches your computer. It is an early-warning sensor for *this* PC, not a whole-network scanner.
- Blocking an address helps against a single attacker, but serious attackers hop between many addresses, so blocking one is a **speed bump, not a wall**. The real protection is keeping your PC patched, your firewall closed to the outside, and antivirus switched on. Intrusion Monitor is an extra pair of eyes, not a replacement for those.
- The tamper-evidence proves the records weren't changed *after* they were written. Keep exported packs (and their fingerprints) somewhere other than the PC being attacked.
- The list of known-bad ARTEX addresses is from public reporting in October–November 2026. Attackers change addresses, so that part of the detection ages; the scan, tripwire and connection-counting detections don't.

---

## Logs and settings

Everything is saved in the `logs` folder next to the script:

| File | Contents |
|------|----------|
| `Evidence_YYYYMMDD.jsonl` | The tamper-evident evidence journal (one per UTC day). |
| `Evidence_YYYYMMDD.seal.txt`, `Seals.txt` | Each day's seal fingerprint. |
| `Connections_YYYYMMDD.csv` | One line per incoming attempt — opens in Excel. |
| `ConnectionSummary.csv` | One line per address: totals, ports, who, where, abuse contact. |
| `IntrusionMonitor_YYYYMMDD.log` | Plain-text activity log. |
| `export\EvidencePack_*.zip` | Evidence packs you've exported, with `.sha256.txt` fingerprints. |

The `data` folder holds the list of network-device makers (downloaded automatically).

Advanced users can change colours, text size, how often it checks, and which features are on (lookups, automatic traceroute, clock checks) by editing the settings block at the top of `IntrusionMonitor.ps1`. You don't need to touch it to use the tool.

To check an evidence folder from a command line:
`powershell -ExecutionPolicy Bypass -File IntrusionMonitor.ps1 -VerifyDir <folder>`

---

## Uninstall

There's nothing to uninstall. Close the window and delete the folder. If you used the admin version and it added firewall blocks, press **Clear blocks** before closing (or they'll stay until you remove them). Keep any evidence packs you need first.

---

## Credits

- **Author:** RuneLore63
- **Contributor:** Matt ([@mattnmorgan](https://github.com/mattnmorgan))

## Licence

Released under the MIT Licence — free to use, change and share. See [LICENSE](LICENSE).

## Disclaimer

Intrusion Monitor is a defensive early-warning aid, provided as-is with no warranty. Use it only on computers you own or are authorised to monitor. It does not guarantee detection of every threat and is not a substitute for a maintained operating system, firewall and antivirus. It is not legal advice; ask the police or a solicitor how evidence should be handled in your case.
