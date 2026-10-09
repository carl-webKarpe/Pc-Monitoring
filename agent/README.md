# MST Monitoring Agent (Phases 8 and 13)

A small Python program that runs on each **authorized** lab computer. It:

- identifies the computer to the MST server with a device ID and a private device token;
- sends a **heartbeat** every 30 seconds (online status, hostname, IP, MAC, Windows version, CPU, memory, disk);
- watches **only the folders you list** (by default Downloads, Desktop, Documents) and reports **new, modified, renamed and deleted** files: name, location, size, time, SHA-256 fingerprint and download evidence;
- keeps events in a local queue (`mst_agent_queue.db`) when the server cannot be reached and sends them later.

New files are scanned on this PC (antivirus engines + static analysis) automatically or when an Admin clicks **Scan**; see *Scanning and quarantine* below. It only scans files inside its watch folders.

It does **not** upload file contents, record keystrokes, capture the screen, control the computer, or hide itself. It runs as a normal visible program and writes everything it does to `mst_agent.log`.

## 1. On the MST server (admin laptop) — once

1. Find the laptop's IP address: run `ipconfig` and note the **IPv4 Address** (e.g. `192.168.1.10`).
2. Set the network to **Private**: Settings → Network & Internet → Wi-Fi (or Ethernet) → your network → *Private*.
3. Allow lab PCs to reach the API (PowerShell **as administrator**, once):
   ```powershell
   New-NetFirewallRule -DisplayName "MST API 8081" -Direction Inbound -Protocol TCP -LocalPort 8081 -Action Allow -Profile Private
   ```
4. Start the API so the lab PCs can reach it over the LAN (`0.0.0.0` = all network cards):
   ```powershell
   cd C:\xampp1\htdocs\monitoring
   php -S 0.0.0.0:8081 backend/public/index.php
   ```
5. Register each lab PC with its own device ID:
   ```powershell
   php backend/tools/register-agent.php MST-PC-003 LAB-PC-03
   ```
   Copy the `device_token` it prints. The token is shown only once; running the command again issues a new token.

## 2. On each lab PC

1. Install **Python 3.10+** from python.org (tick **"Add python.exe to PATH"**).
2. Copy the `agent` folder to the PC, e.g. `C:\MST\agent`.
3. Check that the PC can reach the server: open `http://192.168.1.10:8081/api/` (the laptop's IP) in a browser. It must show `"message":"MST API"`.
4. Install the agent in its own Python environment:
   ```powershell
   cd C:\MST\agent
   python -m venv .venv
   .venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   copy config.example.json config.json
   notepad config.json
   ```
5. In `config.json` set:
   - `server_url`: `http://<admin-laptop-IP>:8081/api` (e.g. `http://192.168.1.10:8081/api`)
   - `device_id` and `device_token`: from step 1.5
   - `watch_folders`: the folders to monitor. `{Downloads}`, `{Desktop}` and `{Documents}` use the folders' real locations from Windows, so they also work when OneDrive has moved Desktop/Documents. You can also list full paths (`%USERPROFILE%` means the logged-in user's folder).
6. Test the connection (sends one heartbeat and exits):
   ```powershell
   python run_agent.py --check
   ```
   `Heartbeat accepted by the MST server.` means it works; the PC now shows as online on the dashboard.
7. Run the agent: double-click **`start-agent.bat`** (or `python run_agent.py`). Keep the window open; close it or press **Ctrl+C** to stop. Only one agent can run at a time: a second copy says *Another MST agent is already running* and exits.

## 3. Start automatically when someone signs in (recommended)

In PowerShell, in the agent folder:
```powershell
powershell -ExecutionPolicy Bypass -File .\install-autostart.ps1
```
It checks the connection first, then creates the Windows scheduled task **"MST Monitoring Agent"**, which starts `start-agent.bat` every time **this Windows user** signs in (the agent watches that user's Downloads, Desktop and Documents, so install it while signed in as the account students use). If the agent stops unexpectedly, the window restarts it after 30 seconds.

- The agent window stays **visible** (titled *MST Monitoring Agent*): lab monitoring is never hidden. You can minimize it.
- To remove the automatic start: `powershell -ExecutionPolicy Bypass -File .\uninstall-autostart.ps1`
- Several Windows accounts on one PC: run the install script once while signed in to each account (each account's agent uses the same `config.json`; only one runs at a time).

To try the file watcher without a server: `python run_agent.py --offline` prints each event on screen.

## Config options

| Key | Meaning |
|---|---|
| `server_url` | MST API base URL |
| `device_id`, `device_token` | This PC's identity (from `register-agent.php`) |
| `heartbeat_interval_seconds` | How often to report status (default 30) |
| `watch_folders`, `recursive` | Folders to monitor and whether to include sub-folders |
| `ignore_extensions`, `ignore_name_prefixes` | Temporary files to skip (browser partial downloads, Office lock files) |
| `max_hash_size_mb` | Files larger than this are reported without a SHA-256 (default 200 MB) |
| `tls_ca_bundle` | Certificate file to trust when `server_url` is `https://` with a lab/self-signed certificate (empty = normal certificate checks) |
| `queue_file`, `log_file` | Local queue and log file (next to `config.json` by default) |
| `antivirus` | `auto` (every installed engine), `defender`, `clamav` or `none`. Microsoft Defender is built into Windows and is found automatically |
| `clamav_path`, `defender_path` | Only if MST cannot find `clamscan.exe` / `MpCmdRun.exe` by itself |
| `scan_timeout_seconds` | Longest time one antivirus scan may take (default 120) |
| `quarantine_folder` | Where quarantined files are kept (default `quarantine` next to `config.json`; must not be inside a watch folder) |

## Scanning and quarantine (Phase 13)

- Scans are run when an Admin clicks **Scan**, or automatically for every new file when *Settings → Scanner → Automatically scan new files* is on.
- For each scan the agent hashes the file, identifies its real type, looks for risk indicators (disguised programs, macros, active PDF content, programs inside archives, suspicious script commands) and runs the installed antivirus engines. **Files are never opened or run, and never uploaded**: only the SHA-256 is checked on VirusTotal (by the server).
- The agent log shows the engines it found at start-up, e.g. `Antivirus engine: Microsoft Defender 4.18... - Ready`. If it says *No antivirus engine is available*, results rely on VirusTotal and static analysis only.
- **Quarantine** (Admin, with confirmation): the agent moves the file to `quarantine_folder` as `<id>-<hash>.quarantined` (read-only, cannot be double-clicked to run), but only if the file is still in a watch folder and its SHA-256 is unchanged. **Release** puts it back; **Delete** removes it permanently.
- File activity reported: new files, real content changes (*modified*), renames, deletions, and how a file arrived: *Browser download completed* (temporary `.crdownload`/`.part` file renamed) or *Downloaded (confirmed)* when Windows' Mark of the Web shows it came from the internet (with the source site when the browser recorded it).

## Troubleshooting

| Message | Fix |
|---|---|
| `Another MST agent is already running` | An agent is already running on this PC (check the taskbar for the *MST Monitoring Agent* window). Only one copy runs at a time. |
| The lab PC cannot open `http://<laptop-IP>:8081/api/` | Check the laptop IP with `ipconfig` (it can change), that the API runs with `0.0.0.0:8081`, the firewall rule (section 1.3) and that the network is *Private*. School Wi-Fi often blocks PC-to-PC traffic: use a phone hotspot or a small router. |
| `MST server not reachable` | Check the admin laptop IP in `server_url`, that the API runs with `0.0.0.0:8081`, and that Windows Firewall on the laptop allows port 8081 (Phase 10). Events are kept and sent later. |
| `Device not authorized` | `device_id`/`device_token` do not match, or the PC was revoked (`register-agent.php --revoke`). Run `register-agent.php` again and paste the new token. |
| `HTTPS certificate of the MST server is not trusted` | The server uses its own certificate: copy it next to `config.json` and set `"tls_ca_bundle": "mst.crt"` (see `SECURITY.md`). |
| `Watch folder does not exist and is skipped` | Fix the path in `watch_folders`. |
| A scan says *Microsoft Defender: The file disappeared during the scan* | Defender's real-time protection removed the file itself (normal for the EICAR test file). |
| Quarantine failed: *has changed since it was scanned* | The file was edited after the scan. Scan it again, then quarantine. |
| The PC still shows demo values ("10 sec ago", MAC *Unavailable*) | The agent has not connected: run `python run_agent.py --check` on the PC and read the message; make sure the same `device_id` was registered with `register-agent.php`. Then press Ctrl+F5 on the dashboard. |
| A downloaded file does not appear | The agent must be running (`python run_agent.py`, window open) and the file must be in a folder listed in `watch_folders`. Check `mst_agent.log`. Temporary files (`.crdownload`, `~$...`) are ignored on purpose. |

## Tests (developers)

```powershell
python -m pip install pytest
python -m pytest tests
```
