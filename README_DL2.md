# Series 3 Emitter — v1_0(py38-safe) for DL2

**Target**: Windows 7 + Python 3.8.10  
**Baseline**: v5_4 (no logic changes)

## Files
- series3_emitter_v1_0_py38.py — main script (py38-safe)
- config.ini — your config (already included)
- series3_roster.csv — your roster (already included, this auto updates from a URL to a dropbox file)
- requirements.txt — none beyond stdlib

## Install
1) Create `C:\SeismoEmitter\` on DL2
2) Extract this ZIP into that folder
3) Open CMD:
   ```cmd
   cd C:\SeismoEmitter
   python series3_emitter_v1_0_py38.py
   ```
(If the console shows escape codes on Win7, set `COLORIZE = False` in `config.ini`.)

## Quick validation
- Heartbeat prints Local/UTC timestamps
- One line per active roster unit with OK/Pending/Missing, Age, Last, File
- Unexpected units block shows .MLG not in roster
- emitter.log rotates per LOG_RETENTION_DAYS
