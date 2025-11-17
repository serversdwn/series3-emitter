A lightweight Python script that monitors Instantel **Series 3 (Minimate)** call-in activity on a Blastware server.

It scans the event folder, reads `.MLG` headers to identify unit IDs, and prints a live status table showing:

- Last event received  
- Age since last call-in  
- OK / Pending / Missing states  
- Bench and ignored units  
- Unexpected units  
- Notes from the roster file  

This script is part of the larger **Seismograph Fleet Manager** project.

---

## Requirements

- Python 3.8 (Windows 7 compatible)  
- Blastware 10 event folder available locally  
- `series3_roster.csv` in the configured path  
- `config.ini` in the same directory as the script  

Install dependencies with:

`pip install -r requirements.txt`

---

## Usage

Run the emitter from the folder containing the script:

`python series3_emitter.py`

The script will:

1. Load the roster file  
2. Scan the Blastware event folder for `.MLG` files  
3. Sniff each file header for the unit ID  
4. Print a status line for each active unit  
5. Refresh the roster automatically if `ROSTER_URL` is set  
6. Write logs into the `emitter_logs/` folder  

---

## Config

All settings are stored in `config.ini`.

Key fields:

- `SERIES3_PATH` – folder containing `.MLG` files  
- `ROSTER_FILE` – path to the local roster CSV  
- `ROSTER_URL` – optional URL for automatic roster downloads  
- `SCAN_INTERVAL_SECONDS` – how often to scan  
- `OK_HOURS` / `MISSING_HOURS` – thresholds for status  

---

## Logs

Logs are stored under `emitter_logs/`.  
Git ignores all log files but keeps the folder itself.

---

## Versioning

This repo follows **Semantic Versioning (SemVer)**.

Current release: **v1.0.0** – stable baseline emitter.  
See `CHANGELOG.md` for details.

---

## License

Private / internal project.
```