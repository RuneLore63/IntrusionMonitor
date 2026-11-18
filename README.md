# Intrusion Monitor

**A free, no-install early-warning tool for Windows. It watches your PC and warns you — in plain English — the moment something starts probing your machine or your PC contacts a known-bad address on the internet. It shows you who is behind the connection and gives you a one-click button to cut it off.**

Built for ordinary PC users, not just security professionals. No installer, no background service you have to trust, no account. It is a single script you double-click, and you can close it any time.

---

## What it does

When it's running, Intrusion Monitor quietly keeps an eye on your own computer and raises a big, easy-to-read alert if it sees any of these:

- **Someone scanning your PC** — a tell-tale burst of probes against lots of your ports at once, the way automated attack tools start.
- **Your PC contacting a known-bad address** — connections or web lookups to internet infrastructure linked to the ARTEX automated-attack toolkit.
- **A tripwire being touched** — it quietly puts a tempting-looking decoy folder (and, if allowed, a decoy network share) in place; if anything pokes at it, you hear about it immediately. Nothing legitimate ever touches that folder, so an alert there is a real signal.
- **New devices appearing** on your local network (shown as information, not an alarm).
- **Every incoming connection attempt, counted per address** — who has tried to connect to your PC, how many times, whether they were refused or let in, and every port number they tried. Press **Connections** to see the table.

Each address is labelled by where it comes from, so your own programs never set off an alarm:

| From | What it is | What happens |
|------|-----------|--------------|
| **This PC** | 127.0.0.1 and your PC's own addresses — programs on your computer talking to each other | Listed in grey. **Never** alarms. |
| **Home network** | 192.168.x.x, 10.x.x.x and similar — your router, phones, TV, other PCs | Listed. A scan or repeated refusals gives an amber warning only. |
| **Internet** | Everything else | Can raise the red alarm and the Disconnect & Block pop-up. |

When the alert involves an internet address, the pop-up tells you **where it's coming from** — country, internet provider, and who owns the address — and gives you a **Disconnect & Block** button that slams the door on that address at the Windows Firewall.

Everything it sees is written to a dated log file so you have a record.

---

## Download and install

You don't really "install" it — you just download it and run it.

1. On this page, click the green **Code** button, then **Download ZIP** (or grab the ZIP from the **Releases** section if one is published).
2. Find the downloaded `IntrusionMonitor.zip` (usually in your **Downloads** folder), **right-click it**, and choose **Extract All…**, then **Extract**.
3. Open the extracted **IntrusionMonitor** folder.
4. Double-click **`IntrusionMonitor.vbs`**. It starts silently in the background — no black command window — and sits minimised until it sees something.
5. The first time, Windows may show a blue **"Windows protected your PC"** box, because the tool isn't signed by a big company. Click **More info**, then **Run anyway**. *(Normal for free, open tools.)*
6. That's it — it's watching. The window only pops open when there's an alert to show you; otherwise it stays out of your way.

To stop it, open the window (it pops up on an alert, or click its taskbar icon) and press **Stop**.

### Turning on blocking (optional)

Blocking attackers needs Administrator rights, so it's off until you ask for it. In the monitor window, press **Elevate** and answer **Yes** to the Windows prompt. It reopens in full mode, adding the **Disconnect & Block** button and inbound port-scan detection. Your own router and PC are never blockable, so you can't cut yourself off.

---

## Understanding the alerts

| Colour | Meaning |
|--------|---------|
| **Red (HIGH)** | Something that deserves your attention now — a scan, a known-bad connection, or a tripwire hit. |
| **Orange (MED)** | Worth noticing — a suspicious name lookup, for example. |
| **Amber (INFO)** | Just information — the tool starting, or a new device on your network. |

A red alert with an internet address will pop its own window showing who's behind it and a **Disconnect & Block** button.

---

## What it can't do (so you're not misled)

- It watches **your own PC**. On a normal home or office network it **cannot** see attacks against your neighbour's machine — that traffic never reaches your computer. It is an early-warning sensor for *this* PC, not a whole-network scanner.
- Blocking an address helps against a single attacker, but serious attackers hop between many addresses, so blocking one is a **speed bump, not a wall**. The real protection is keeping your PC patched, your firewall closed to the outside, and antivirus switched on. Intrusion Monitor is an extra pair of eyes, not a replacement for those.

---

## Logs and settings

- Logs are saved in the `logs` folder next to the script, one file per day.
- `Connections_YYYYMMDD.csv` has one line for every incoming attempt: time, address, where it's from, port, protocol, and whether it was refused or let in. `ConnectionSummary.csv` has one line per address with its totals and every port it tried. Both open in Excel. The **Open logs** button in the Connections window takes you straight there.
- Without admin rights, only connections that actually reached your PC can be counted. Press **Elevate** to count the refused ones as well — that's where scans show up.
- Advanced users can change colours, text size, how often it checks, and which features are on by editing the settings block at the top of `IntrusionMonitor.ps1`. You don't need to touch it to use the tool.

---

## Uninstall

There's nothing to uninstall. Close the window and delete the folder. If you used the admin version and it added firewall blocks, press **Clear blocks** before closing (or they'll stay until you remove them).

---

## Credits

- **Author:** RuneLore63
- **Contributor:** Matt ([@mattnmorgan](https://github.com/mattnmorgan))

## Licence

Released under the MIT Licence — free to use, change and share. See [LICENSE](LICENSE).

## Disclaimer

Intrusion Monitor is a defensive early-warning aid, provided as-is with no warranty. Use it only on computers you own or are authorised to monitor. It does not guarantee detection of every threat and is not a substitute for a maintained operating system, firewall and antivirus.
