# MST Monitoring Agent (Phase 8)

A small Python program that runs on each **authorized** lab computer. It:

- identifies the computer to the MST server with a device ID and a private device token;
- sends a **heartbeat** every 30 seconds (online status, hostname, IP, MAC, Windows version, CPU, memory, disk);
- watches **only the folders you list** (by default Downloads, Desktop, Documents) and reports **new** and **deleted** files: name, location, size, time and SHA-256 fingerprint;
- keeps events in a local queue (`mst_agent_queue.db`) when the server cannot be reached and sends them later.

When an Admin clicks **Scan** on the Detected Files page, the agent re-checks that file on this PC and reports the result (see `backend/README.md`, Phase 11). It only scans files inside its watch folders.

It does **not** upload file contents, record keystrokes, capture the screen, control the computer, or hide itself. It runs as a normal visible program and writes everything it does to `mst_agent.log`.

## 1. On the MST server (admin laptop) — once per lab PC

1. Apply the Phase 9 migration once (MySQL Workbench → open `database/migrations/phase9_agent.sql` → Execute).
2. Start the API so the lab PCs can reach it over the LAN:
   ```powershell
   cd C:\xampp1\htdocs\monitoring
   php -S 0.0.0.0:8081 backend/public/index.php
   ```
3. Register the lab PC (use a unique device ID for each PC):
   ```powershell
   php backend/tools/register-agent.php MST-PC-002 LAB-PC-02 192.168.1.21
   ```
   Copy the `device_id` and `device_token` it prints. The token is shown only once; running the command again issues a new token.

## 2. On each lab PC

1. Install **Python 3.10+** from python.org (tick "Add python.exe to PATH").
2. Copy the `agent` folder to the PC, e.g. `C:\MST\agent`.
3. Install the three libraries:
   ```powershell
   cd C:\MST\agent
   python -m pip install -r requirements.txt
   ```
4. Copy `config.example.json` to `config.json` and edit it:
   - `server_url`: `http://<admin-laptop-IP>:8081/api` (e.g. `http://192.168.1.10:8081/api`)
   - `device_id` and `device_token`: from step 1.3
   - `watch_folders`: the folders to monitor (`%USERPROFILE%` means the logged-in user's folder)
5. Test the connection (sends one heartbeat and exits):
   ```powershell
   python run_agent.py --check
   ```
   `Heartbeat accepted by the MST server.` means it works; the PC now shows as online on the dashboard.
6. Run the agent:
   ```powershell
   python run_agent.py
   ```
   Keep the window open. Press **Ctrl+C** to stop it.

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
| `queue_file`, `log_file` | Local queue and log file (next to `config.json` by default) |

## Troubleshooting

| Message | Fix |
|---|---|
| `MST server not reachable` | Check the admin laptop IP in `server_url`, that the API runs with `0.0.0.0:8081`, and that Windows Firewall on the laptop allows port 8081 (Phase 10). Events are kept and sent later. |
| `Device not authorized` | `device_id`/`device_token` do not match. Run `register-agent.php` again and paste the new token. |
| `Watch folder does not exist and is skipped` | Fix the path in `watch_folders`. |
| The PC still shows demo values ("10 sec ago", MAC *Unavailable*) | The agent has not connected: run `python run_agent.py --check` on the PC and read the message; make sure the same `device_id` was registered with `register-agent.php`. Then press Ctrl+F5 on the dashboard. |
| A downloaded file does not appear | The agent must be running (`python run_agent.py`, window open) and the file must be in a folder listed in `watch_folders`. Check `mst_agent.log`. Temporary files (`.crdownload`, `~$...`) are ignored on purpose. |

## Tests (developers)

```powershell
python -m pip install pytest
python -m pytest tests
```
