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

## Part 2: Create an enrollment key (server)

1. Open **Computers** and click **Add Computers**.
2. Enter a name (for example `Lab A`), how long the key is valid (for example **8 hours**) and how many PCs it may add.
3. Click **Create Key**. The key is shown **only once**.
4. Click **Download enrollment.txt**. This small file contains the key and the server address.

> Keep the key private while it is active. Anyone with the key could add a computer. When all PCs are added,
> click **Revoke** next to the key. PCs that were already added keep working.

---

## Part 3: Set up each lab PC

**Once on the server, prepare a USB drive:**

1. Copy the folder `C:\xampp1\htdocs\monitoring\agent` to the USB drive.
2. Put the downloaded **enrollment.txt** inside that `agent` folder on the USB drive.
3. Inside the copied folder, delete these if they exist (they belong to the server): `config.json`, `.venv`,
   `quarantine`, `mst_agent.lock`, `mst_agent.log`, `mst_agent_queue.db`.

**On each lab PC:**

1. Install **Python 3 (64-bit)** from <https://www.python.org/downloads/> once, and tick **Add python.exe to PATH**.
2. Copy the `agent` folder from the USB drive to **`C:\MST\agent`** (so that `C:\MST\agent\setup-agent.bat` exists).
3. Double-click **`setup-agent.bat`**. It:
   - installs the agent's packages,
   - enrolls the PC with the key from enrollment.txt (it gets its own device ID, for example `MST-PC-006`),
   - asks whether the agent should start automatically when this Windows user signs in (**Y** is recommended).
4. Wait for **Setup finished**.

No IP address and no token to type. If enrollment.txt is not there, setup asks you to type the key.

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

## Problems

| What you see | What to do |
| --- | --- |
| `Python is not installed on this PC` | Install Python 3 and tick **Add python.exe to PATH**, then run setup-agent.bat again. |
| `Installing the packages failed` | The PC needs internet once for the packages. Or, on the server, run `pip download -r requirements.txt -d wheels --only-binary=:all: --platform win_amd64 --python-version 3.13` inside the agent folder and copy the `wheels` folder with it: setup then works without internet. |
| `The MST server was not found on this network` | The PC and the server are not on the same network, the API is not running (start-server.bat), or port 8081 is blocked (Part 1 firewall). Some school Wi-Fi blocks computer-to-computer connections: use a LAN cable or a phone hotspot. |
| `The enrollment key is wrong, expired, used up or revoked` | Create a new key (Part 2) and replace enrollment.txt. |
| `Too many wrong enrollment keys` | Wait 15 minutes, then use the correct key. |
| PC shows **OFFLINE** | The agent window was closed or the PC is off. Start `C:\MST\agent\start-agent.bat`. |
| `Device not authorized` | The PC's token was replaced. Run setup-agent.bat again (with an active key). |
