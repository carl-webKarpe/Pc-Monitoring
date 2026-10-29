# MST User Guide: adding lab PCs

How to add lab PCs (or other laptops) to MST and watch their downloads. You do **not** need to type an IP address
or a token on each PC: one **enrollment key** adds many PCs, and every PC finds the MST server on the network by itself
(also after the server's IP address changes).

| Word | Meaning |
| --- | --- |
| **Server** | Your laptop that runs MST (API, website, MySQL). |
| **Lab PC** | A PC or laptop whose Downloads, Desktop and Documents are monitored. |
| **Agent** | The small program on each lab PC (`C:\MST\agent`). |
| **Enrollment key** | A short code like `9F5C-ZBNZ-YC5R-FAXR`. It adds PCs until it expires, reaches its PC limit or is revoked. |

Both computers must be on the **same network**: the same Wi-Fi, the same LAN switch, or one LAN cable between them.

---

## Part 1: Start MST on the server

**Once (firewall).** Open PowerShell **as Administrator** and run:

```powershell
New-NetFirewallRule -DisplayName "MST API 8081" -Direction Inbound -Protocol TCP -LocalPort 8081 -Action Allow -Profile Any
```

**Every time.** Make sure MySQL is running, then double-click **`start-server.bat`** in `C:\xampp1\htdocs\monitoring`.
Two windows open (the API and the website; keep them open) and the browser opens the login page. Sign in as **admin**.

---

**This lab's server address is `192.168.0.224`** (the MST laptop on the LAN cable). It is set in the code: downloaded
config.json and enrollment.txt files use `http://192.168.0.224:8081/api`, and agents try that address first. If the
laptop gets another address, set `PUBLIC_API_URL=http://<new IP>:8081/api` in `.env` (or `PUBLIC_API_URL=auto`) and
restart start-server.bat; agents also search the network by themselves.

## Part 2A: Register ONE PC and get its token (server)

Use this when you add PCs one at a time. **No enrollment key is needed.**

1. Open **Computers** and click **Add Computers**. The **One PC** tab is open.
2. Type a name (for example `LAB-PC-07` or `Front desk laptop`) and click **Register Computer**.
3. The PC's **device ID** (for example `MST-PC-007`) and **device token** appear. The token is shown **only once**.
4. Click **Download config.json**. This file already contains the server address, the device ID and the token.
5. Put that **config.json** inside the `agent` folder you copy to the PC (Part 3). `setup-agent.bat` uses it and
   does not ask for a key. It also finds it when it is named `config (1).json`, or when it is still in that PC's
   **Downloads** folder (the newest one is used; the old config.json is kept as `config.json.bak`).

The PC shows on the Computers list right away as **OFFLINE** until its agent runs. It keeps the name you typed;
its Windows computer name is shown under it once it connects.

**Rename / Delete:** each row on **Computers** has **Rename** (your own name; leave it empty to show the Windows name)
and **Delete** (type `DELETE`). Delete removes the PC, its detected-file list and its quarantine records, and its agent
can no longer connect. Scan results, threats and Activity Logs are kept.

**Lost the token, or a PC was replaced?** Click **View** on that computer, then **New Token** (the old token stops
working; download the new config.json). **Revoke Access** stops a PC from sending data; its history is kept.

## Part 2B: Create an enrollment key for MANY PCs (server)

Use this to add a whole lab with one code.

1. Open **Computers**, click **Add Computers** and choose the **Many PCs (enrollment key)** tab.
2. Enter a name (for example `Lab A`), how long the key is valid (for example **8 hours**) and how many PCs it may add.
3. Click **Create Key**. The key is shown **only once**.
4. Click **Download enrollment.txt**. This small file contains the key and the server address.

> Keep the key private while it is active. Anyone with the key could add a computer. When all PCs are added,
> click **Revoke** next to the key. PCs that were already added keep working.

---

## Part 3: Set up each lab PC

**Once on the server, prepare a USB drive:**

1. Copy the folder `C:\xampp1\htdocs\monitoring\agent` to the USB drive.
2. Inside the copied folder, delete these if they exist (they belong to the server): `config.json`, `.venv`,
   `quarantine`, `mst_agent.lock`, `mst_agent.log`, `mst_agent_queue.db`.
3. Then put the downloaded file inside that `agent` folder on the USB drive: **config.json** (one PC, Part 2A) or
   **enrollment.txt** (many PCs, Part 2B).

**On each lab PC:**

1. Install **Python 3 (64-bit)** from <https://www.python.org/downloads/> once, and tick **Add python.exe to PATH**.
2. Copy the `agent` folder from the USB drive to **`C:\MST\agent`** (so that `C:\MST\agent\setup-agent.bat` exists).
3. Double-click **`setup-agent.bat`**. It:
   - installs the agent's packages,
   - with **config.json**: checks the connection (and finds the server if its address changed);
   - with **enrollment.txt**: enrolls the PC with the key (it gets its own device ID, for example `MST-PC-006`);
   - asks whether the agent should start automatically when this Windows user signs in (**Y** is recommended).
4. Wait for **Setup finished**.

No IP address and no token to type. If neither file is there (not in `C:\MST\agent` and no config.json in
Downloads), setup explains both ways and asks for an enrollment key; press **Enter** to stop instead.

If the PC has its config.json but the server does not answer, setup now says so and asks **R** (try again),
**K** (use an enrollment key instead) or **S** (skip). Check that `start-server.bat` is running on the server, that
both are on the same network, and that port 8081 is allowed in the server's firewall.

---

## Part 4: Check that it works

1. On the server, open **Computers** and click **Refresh**. The new PC shows **ONLINE** with its real name and IP.
2. On the lab PC, download any file with Chrome or Edge.
3. On the server, open **Detected Files**. The file appears within a few seconds as **New file**, downloaded,
   with the website it came from and its scan result.

---

## Part 5: When the server's IP address changes

Nothing to do. When the agent cannot reach the server, it searches the network for it (about every 5 minutes), checks
that it is the real MST server, saves the new address and sends everything it detected in the meantime.

To search right away on a lab PC: `cd C:\MST\agent` then `.\.venv\Scripts\python.exe run_agent.py --find-server`.

---

## Part 6: Manage enrollment keys

**Computers > Add Computers** lists the keys: how many PCs each one added, when it expires and its status
(**ACTIVE**, **USED UP**, **EXPIRED** or **REVOKED**). Creating a key, every PC that enrolls, every refused key and
every revoke is recorded in **Activity Logs**.

Running `setup-agent.bat` again on a PC that is already enrolled does not create a second entry: the same PC (same
computer name and network adapter) keeps its device ID.

---

## Part 7: Deleted files (File Explorer, Recycle Bin, USB drives)

With agent **1.3** or newer, every deletion shows **which PC**, **which file** (full original path) and **when**:

| What you see on Detected Files | What happened on the PC |
| --- | --- |
| **DELETED · Moved to Recycle Bin** | Deleted with File Explorer (Delete key). Reported from **any folder** on the drive, with the real delete time. A folder shows **FOLDER DELETED** instead of DELETED. |
| **DELETED · Deleted permanently** | Deleted without the Recycle Bin: Shift+Delete, a USB drive, a program or the command line. |
| **DELETED · Removed from Recycle Bin** | The Recycle Bin was emptied (or the item was deleted there): it is now permanently gone. |
| **DELETED** (no second line) | The agent could not tell how: Recycle Bin watching is turned off, or that drive's Recycle Bin could not be read. |

**Deleted folders (agent 1.4).** A deleted folder is reported like a deleted file, as **one row**:
**FOLDER DELETED** with the same second line (Moved to Recycle Bin, Deleted permanently, Removed from Recycle Bin).
This works for every way of deleting it: Delete key, Shift+Delete, emptying the Recycle Bin, a USB drive, the
command line, and also for an empty folder. The files inside a deleted folder are not listed one by one; the folder's
row stands for all of them (the agent's log shows how many files were inside). Choose **Activity > Deleted folders**
to see only folders.

Restoring a file from the Recycle Bin is not a deletion and is not reported as one. Items moved to the Recycle Bin
while the agent was not running are reported when it starts again, with their real delete time.

Use **Activity** on Detected Files to show only one kind (for example **Deleted permanently**). **View** shows
**How It Was Deleted** and **Deleted At**.

**Watching more of the PC.** New config.json files (from Register Computer) watch:
`{UserProfile}` (the whole user folder), `{OtherDrives}` (D:, E:, ... except the Windows drive) and
`{RemovableDrives}` (USB drives while plugged in). Windows and program folders that change all the time (AppData,
Temp, Program Files, .git, ...) are ignored; the list is `ignore_folders` in config.json.

**Updating a PC that already runs the agent:**

1. Copy the new `mst_agent` folder (and `config.example.json`) over the old ones in `C:\MST\agent`. Keep the PC's own `config.json`.
2. Recycle Bin and permanent-delete detection then work right away.
3. To also watch the whole user folder, other drives and USB drives, open `config.json` and change the
   `watch_folders` lines to:

   ```json
   "watch_folders": ["{UserProfile}", "{OtherDrives}", "{RemovableDrives}"],
   ```
4. Restart the agent (close its window and run `start-agent.bat`, or sign out and in).

What MST cannot see: a permanent delete (Shift+Delete) that happened while the agent was not running, and which program
or Windows user deleted a file (that needs Windows auditing, a possible later "precise mode").

---

## Problems

| What you see | What to do |
| --- | --- |
| `Python is not installed on this PC` | Install Python 3 and tick **Add python.exe to PATH**, then run setup-agent.bat again. |
| `Installing the packages failed` | The PC needs internet once for the packages. Or, on the server, run `pip download -r requirements.txt -d wheels --only-binary=:all: --platform win_amd64 --python-version 3.13` inside the agent folder and copy the `wheels` folder with it: setup then works without internet. |
| `The MST server was not found on this network` | The PC and the server are not on the same network, the API is not running (start-server.bat), or port 8081 is blocked (Part 1 firewall). Some school Wi-Fi blocks computer-to-computer connections: use a LAN cable or a phone hotspot. |
| `The enrollment key is wrong, expired, used up or revoked` | Create a new key (Part 2) and replace enrollment.txt. |
| `Too many wrong enrollment keys` | Wait 15 minutes, then use the correct key. |
| PC shows **OFFLINE** | The agent window was closed or the PC is off. Start `C:\MST\agent\start-agent.bat`. |
| `Device not authorized` | The PC's token was replaced or revoked. On the server: **View** that computer, **New Token**, then put the new config.json on the PC. Or run setup-agent.bat again with an active enrollment key. |
