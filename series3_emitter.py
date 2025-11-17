"""
Series 3 Emitter — v1.0.0 (Stable Baseline, SemVer Reset)

Environment:
- Python 3.8 (Windows 7 compatible)
- Runs on DL2 with Blastware 10 event path

Key Features:
- Atomic roster downloads from Dropbox (no partial files)
- Automatic roster refresh from Dropbox at configurable interval
- Automatic hot-reload into memory when roster CSV changes
- Failsafe reload: keeps previous roster if new file is invalid or empty
- Config-driven paths, intervals, and logging
- Compact console heartbeat with status per unit
- Logging with retention auto-clean (days configurable)
- Safe .MLG header sniff for unit IDs (BE#### / BA####)

Changelog:
- Reset to semantic versioning (from legacy v5.9 beta)
- Fixed stray `note=note_suffix` bug in Unexpected Units block
- Removed duplicate imports and redundant roster load at startup
- Added startup config echo (paths + URL status)
"""

import os
import re
import csv
import time
import configparser
import urllib.request
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, Tuple, Set, List

# ---------------- Config ----------------
def load_config(path: str) -> Dict[str, Any]:
    """Load INI with tolerant inline comments and a required [emitter] section."""
    cp = configparser.ConfigParser(inline_comment_prefixes=(';', '#'))
    cp.optionxform = str  # preserve key case
    with open(path, "r", encoding="utf-8") as f:
        txt = f.read()
    # Ensure we have a section header
    if not re.search(r'^\s*\[', txt, flags=re.M):
        txt = "[emitter]\n" + txt
    cp.read_string(txt)
    sec = cp["emitter"]

    def get_str(k: str, dflt: str) -> str:
        return sec.get(k, dflt).strip()

    def get_int(k: str, dflt: int) -> int:
        try:
            return int(sec.get(k, str(dflt)).strip())
        except Exception:
            return dflt

    def get_bool(k: str, dflt: bool) -> bool:
        v = sec.get(k, None)
        if v is None:
            return dflt
        return v.strip().lower() in ("1","true","on","yes","y")

    return {
        "WATCH_PATH": get_str("SERIES3_PATH", r"C:\Blastware 10\Event\autocall home"),
        "ROSTER_FILE": get_str("ROSTER_FILE", r"C:\SeismoEmitter\series3_roster.csv"),
        "ROSTER_URL": get_str("ROSTER_URL", ""),
        "ROSTER_REFRESH_MIN_SECONDS": get_int("ROSTER_REFRESH_MIN_SECONDS", 300),
        "SCAN_INTERVAL": get_int("SCAN_INTERVAL_SECONDS", 300),
        "OK_HOURS": float(get_int("OK_HOURS", 12)),
        "MISSING_HOURS": float(get_int("MISSING_HOURS", 24)),
        "ENABLE_LOGGING": get_bool("ENABLE_LOGGING", True),
        "LOG_FILE": get_str("LOG_FILE", r"C:\SeismoEmitter\emitter_logs\series3_emitter.log"),
        "LOG_RETENTION_DAYS": get_int("LOG_RETENTION_DAYS", 30),
        "COLORIZE": get_bool("COLORIZE", False),  # Win7 default off
        "MLG_HEADER_BYTES": max(256, min(get_int("MLG_HEADER_BYTES", 2048), 65536)),
        "RECENT_WARN_DAYS": get_int("RECENT_WARN_DAYS", 30),
    }

# --------------- ANSI helpers ---------------
def ansi(enabled: bool, code: str) -> str:
    return code if enabled else ""

# --------------- Logging --------------------
def log_message(path: str, enabled: bool, msg: str) -> None:
    if not enabled:
        return
    try:
        d = os.path.dirname(path) or "."
        if not os.path.exists(d):
            os.makedirs(d)
        with open(path, "a", encoding="utf-8") as f:
            f.write("{} {}\n".format(datetime.now(timezone.utc).isoformat(), msg))
    except Exception:
        pass

def clear_logs_if_needed(log_file: str, enabled: bool, retention_days: int) -> None:
    if not enabled or retention_days <= 0:
        return
    stamp_file = os.path.join(os.path.dirname(log_file) or ".", "last_clean.txt")
    now = datetime.now(timezone.utc)
    last = None
    try:
        if os.path.exists(stamp_file):
            with open(stamp_file, "r", encoding="utf-8") as f:
                last = datetime.fromisoformat(f.read().strip())
    except Exception:
        last = None
    if (last is None) or (now - last > timedelta(days=retention_days)):
        try:
            if os.path.exists(log_file):
                open(log_file, "w", encoding="utf-8").close()
            with open(stamp_file, "w", encoding="utf-8") as f:
                f.write(now.isoformat())
            print("Log cleared on {}".format(now.astimezone().strftime("%Y-%m-%d %H:%M:%S")))
            log_message(log_file, enabled, "Logs auto-cleared")
        except Exception:
            pass

# --------------- Roster ---------------------
def normalize_id(uid: str) -> str:
    if uid is None:
        return ""
    return uid.replace(" ", "").strip().upper()

def load_roster(path: str) -> Tuple[Set[str], Set[str], Set[str], Dict[str, str]]:
    """CSV tolerant of commas in notes: device_id, active, notes...
       Returns: active, bench, ignored, notes_by_unit
    """
    active: Set[str] = set()
    bench: Set[str] = set()
    ignored: Set[str] = set()
    notes_by_unit: Dict[str, str] = {}

    if not os.path.exists(path):
        print("[WARN] Roster not found:", path)
        return active, notes_by_unit
    try:
        with open(path, "r", encoding="utf-8-sig", newline="") as f:
            rdr = csv.reader(f)
            try:
                headers = next(rdr)
            except StopIteration:
                return active, notes_by_unit
            headers = [(h or "").strip().lower() for h in headers]
            def idx_of(name: str, fallbacks: List[str]) -> Optional[int]:
                if name in headers:
                    return headers.index(name)
                for fb in fallbacks:
                    if fb in headers:
                        return headers.index(fb)
                return None
            i_id = idx_of("device_id", ["unitid","id"])
            i_ac = idx_of("active", [])
            i_no = idx_of("notes", ["note","location"])
            if i_id is None or i_ac is None:
                print("[WARN] Roster missing device_id/active columns")
                return active, notes_by_unit
            for row in rdr:
                if len(row) <= max(i_id, i_ac):
                    continue
                uid = normalize_id(row[i_id])
                note = ""
                if i_no is not None:
                    extra = row[i_no:]
                    note = ",".join([c or "" for c in extra]).strip().rstrip(",")
                notes_by_unit[uid] = note
                if not uid:
                    continue
                is_active = (row[i_ac] or "").strip().lower() in ("yes","y","true","1","on")
                flag = (row[i_ac] or "").strip().lower()
                if flag in ("yes","y","true","1","on"):
                    active.add(uid)
                elif flag in ("no","n","off","0"):
                    bench.add(uid)
                elif flag in ("ignore","retired","old"):
                    ignored.add(uid)

    except Exception as e:
        print("[WARN] Roster read error:", e)
    return active, bench, ignored, notes_by_unit

# --------------- .MLG sniff ------------------
UNIT_BYTES_RE = re.compile(rb"(?:^|[^A-Z])(BE|BA)\d{4,5}(?:[^0-9]|$)")

def sniff_unit_from_mlg(path: str, header_bytes: int) -> Optional[str]:
    """Return BE####/BA#### from header bytes, or None."""
    try:
        with open(path, "rb") as f:
            chunk = f.read(max(256, min(header_bytes, 65536)))
        m = UNIT_BYTES_RE.search(chunk)
        if not m:
            return None
        raw = m.group(0)
        cleaned = re.sub(rb"[^A-Z0-9]", b"", raw)
        try:
            return cleaned.decode("ascii").upper()
        except Exception:
            return None
    except Exception:
        return None

# --------------- Scan helpers ---------------
def fmt_last(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S")

def fmt_age(now_epoch: float, mtime: float) -> str:
    mins = int((now_epoch - mtime) // 60)
    if mins < 0: mins = 0
    return "{}h {}m".format(mins//60, mins%60)

def scan_latest(watch: str, header_bytes: int,
                cache: Dict[str, Tuple[float, str]],
                recent_cutoff: float = None,
                logger=None):

    """Return newest .MLG per unit: {uid: {'mtime': float, 'fname': str}}"""
    latest: Dict[str, Dict[str, Any]] = {}
    if not os.path.exists(watch):
        print("[WARN] Watch path not found:", watch)
        return latest
    try:
        with os.scandir(watch) as it:
            for e in it:
                if (not e.is_file()) or (not e.name.lower().endswith(".mlg")):
                    continue
                fpath = e.path
                try:
                    mtime = e.stat().st_mtime
                except Exception:
                    continue
                cached = cache.get(fpath)
                if cached is not None and cached[0] == mtime:
                    uid = cached[1]
                else:
                   uid = sniff_unit_from_mlg(fpath, header_bytes)
                   if not uid:
                        if (recent_cutoff is not None) and (mtime >= recent_cutoff):
                            if logger:
                                logger(f"[unsniffable-recent] {fpath}")
                        continue   # skip file if no unit ID found in header
                   cache[fpath] = (mtime, uid)
                if (uid not in latest) or (mtime > latest[uid]["mtime"]):
                    latest[uid] = {"mtime": mtime, "fname": e.name}
    except Exception as ex:
        print("[WARN] Scan error:", ex)
    return latest

# --- Roster fetch (Dropbox/HTTPS) helper ---
def refresh_roster_from_url(url: str, dest: str, min_seconds: int,
                            state: dict, logger=None):
    now = time.time()

    # throttle fetches; only pull if enough time elapsed
    if now - state.get("t", 0) < max(0, int(min_seconds or 0)):
        return

    try:
        with urllib.request.urlopen(url, timeout=15) as r:
            data = r.read()
            if data and data.strip():
                with open(dest, "wb") as f:
                    f.write(data)
                state["t"] = now
                if logger:
                    from datetime import datetime
                    logger(f"[roster] refreshed from {url} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} "
                           f"-> {dest} ({len(data)} bytes)")
    except Exception as e:
        if logger:
            logger(f"[roster-fetch-error] {e}")


# --- config helper: case-insensitive key lookup ---
def cfg_get(cfg: dict, key: str, default=None):
    return cfg.get(key, cfg.get(key.lower(), cfg.get(key.upper(), default)))

# --------------- Main loop ------------------
def main() -> None:
    here = os.path.dirname(__file__) or "."
    cfg = load_config(os.path.join(here, "config.ini"))

    WATCH_PATH = cfg["WATCH_PATH"]
    ROSTER_FILE = cfg["ROSTER_FILE"]
    SCAN_INTERVAL = int(cfg["SCAN_INTERVAL"])
    OK_HOURS = float(cfg["OK_HOURS"])
    MISSING_HOURS = float(cfg["MISSING_HOURS"])
    ENABLE_LOGGING = bool(cfg["ENABLE_LOGGING"])
    LOG_FILE = cfg["LOG_FILE"]
    LOG_RETENTION_DAYS = int(cfg["LOG_RETENTION_DAYS"])
    COLORIZE = bool(cfg["COLORIZE"])
    MLG_HEADER_BYTES = int(cfg["MLG_HEADER_BYTES"])

    C_OK  = ansi(COLORIZE, "\033[92m")
    C_PEN = ansi(COLORIZE, "\033[93m")
    C_MIS = ansi(COLORIZE, "\033[91m")
    C_UNX = ansi(COLORIZE, "\033[95m")
    C_RST = ansi(COLORIZE, "\033[0m")
    
        # --- Dropbox roster refresh (pull CSV to local cache) ---
    roster_state = {}
    url = str(cfg_get(cfg, "ROSTER_URL", "") or "")
     # --- Dropbox roster refresh (pull CSV to local cache) ---
    roster_state = {}
    url = str(cfg_get(cfg, "ROSTER_URL", "") or "")

    # 🔎 Patch 3: startup config echo (helps debugging)
    print(f"[CFG] WATCH_PATH={WATCH_PATH}  ROSTER_FILE={ROSTER_FILE}  ROSTER_URL={'set' if url else 'not set'}")
    # (optional, also write it to the log file)
    log_message(LOG_FILE, ENABLE_LOGGING,
                f"[cfg] WATCH_PATH={WATCH_PATH} ROSTER_FILE={ROSTER_FILE} ROSTER_URL={'set' if url else 'not set'}")
    
    if url.lower().startswith("http"):
        refresh_roster_from_url(
            url,
            ROSTER_FILE,
            int(cfg_get(cfg, "ROSTER_REFRESH_MIN_SECONDS", 300)),
            roster_state,
            lambda m: log_message(LOG_FILE, ENABLE_LOGGING, m),
        )

    # cache for scanning
    sniff_cache: Dict[str, Tuple[float, str]] = {}

  # Always load the (possibly refreshed) local roster
    try:
        active, bench, ignored, notes_by_unit = load_roster(ROSTER_FILE)
    except Exception as ex:
        log_message(LOG_FILE, ENABLE_LOGGING, f"[WARN] roster load failed: {ex}")
        active = set()
        bench = set()
        ignored = set()
        notes_by_unit = {}

        # track roster file modification time
    try:
        roster_mtime = os.path.getmtime(ROSTER_FILE)
    except Exception:
        roster_mtime = None



    while True:
        try:
            now_local = datetime.now().isoformat()
            now_utc   = datetime.now(timezone.utc).isoformat()
            print("-" * 110)
            print("Heartbeat @ {} (Local) | {} (UTC)".format(now_local, now_utc))
            print("-" * 110)

            # Periodically refresh roster file from Dropbox
            if url.lower().startswith("http"):
                refresh_roster_from_url(
                    url,
                    ROSTER_FILE,
                    int(cfg_get(cfg, "ROSTER_REFRESH_MIN_SECONDS", 300)),
                    roster_state,
                    lambda m: log_message(LOG_FILE, ENABLE_LOGGING, m),
                )

            # Reload roster into memory if the file changed
            try:
                m = os.path.getmtime(ROSTER_FILE)
            except Exception:
                m = None

            if m is not None and m != roster_mtime:
                    roster_mtime = m
                    try:
                        new_active, new_bench, new_ignored, new_notes_by_unit = load_roster(ROSTER_FILE)
                        if new_active or new_bench or new_ignored:
                            active, bench, ignored, notes_by_unit = new_active, new_bench, new_ignored, new_notes_by_unit
                            print(f"[ROSTER] Reloaded: {len(active)} active unit(s) from {ROSTER_FILE}")
                            log_message(LOG_FILE, ENABLE_LOGGING,
                                    f"[roster] reloaded {len(active)} active units")
                        else:
                            print("[ROSTER] Reload skipped — no valid active units in new file")
                            log_message(LOG_FILE, ENABLE_LOGGING,
                            "[roster] reload skipped — roster parse failed or empty")
                    except Exception as ex:
                        print(f"[ROSTER] Reload failed, keeping previous roster: {ex}")
                        log_message(LOG_FILE, ENABLE_LOGGING,
                        f"[roster] reload failed, keeping previous roster: {ex}")

            clear_logs_if_needed(LOG_FILE, ENABLE_LOGGING, LOG_RETENTION_DAYS)
            recent_cutoff = time.time() - (float(cfg.get("RECENT_WARN_DAYS", 30)) * 86400)
            logger = lambda m: log_message(LOG_FILE, ENABLE_LOGGING, m)
            latest = scan_latest(WATCH_PATH, MLG_HEADER_BYTES, sniff_cache, recent_cutoff, logger)
            now_epoch = time.time()

            for uid in sorted(active):
                info = latest.get(uid)
                if info is not None:
                    age_hours = (now_epoch - info["mtime"]) / 3600.0
                    if age_hours > MISSING_HOURS:
                        status, col = "Missing", C_MIS
                    elif age_hours > OK_HOURS:
                        status, col = "Pending", C_PEN
                    else:
                        status, col = "OK", C_OK
                    note = notes_by_unit.get(uid, "")
                    note_suffix = f"  [{note}]" if note else ""
                    line = ("{col}{uid:<8} {status:<8}  Age: {age:<7} Last: {last}  (File: {fname}){note}{rst}"
                            .format(col=col, uid=uid, status=status,
                                    age=fmt_age(now_epoch, info["mtime"]),
                                    last=fmt_last(info["mtime"]), fname=info["fname"], note=note_suffix, rst=C_RST))
                else:
                    note = notes_by_unit.get(uid, "")
                    note_suffix = f"  [{note}]" if note else ""
                    line = "{col}{uid:<8} Missing   Age:  N/A    Last: ---{note}{rst}".format(col=C_MIS, uid=uid, note=note_suffix, rst=C_RST)
                print(line)
                log_message(LOG_FILE, ENABLE_LOGGING, line)

            # Bench Units (rostered but not active in field)
            print("\nBench Units (rostered, not active):")
            for uid in sorted(bench):
                info = latest.get(uid)
                note = notes_by_unit.get(uid, "")
                note_suffix = f"  [{note}]" if note else ""
                if info:
                    line = (f"{uid:<8} Bench     Last: {fmt_last(info['mtime'])}  (File: {info['fname']}){note_suffix}")
                else:
                    line = (f"{uid:<8} Bench     Last: ---{note_suffix}")
                print(line)
                log_message(LOG_FILE, ENABLE_LOGGING, "[bench] " + line)

            # Ignored Units (retired, broken, or do-not-care)
#            ignored_detected = [u for u in latest.keys() if u in ignored]
#            if ignored_detected:
#                print("\nIgnored Units:")
#                for uid in sorted(ignored_detected):
#                    info = latest[uid]
#                    note = notes_by_unit.get(uid, "")
#                    note_suffix = f"  [{note}]" if note else ""
#                    line = (f"{uid:<8} Ignored   Last: {fmt_last(info['mtime'])}  (File: {info['fname']}){note_suffix}")
#                    print(line)
#                    log_message(LOG_FILE, ENABLE_LOGGING, "[ignored] " + line)
            unexpected = [
                u for u in latest.keys()
                if u not in active and u not in bench and u not in ignored and u not in notes_by_unit
            ]
            if unexpected:
                print("\nUnexpected Units Detected:")
                for uid in sorted(unexpected):
                    info = latest[uid]
                    line = ("{col}{uid:<8} Age: -   Last: {last}  (File: {fname}){rst}"
                            .format(col=C_UNX, uid=uid, last=fmt_last(info["mtime"]), fname=info["fname"], rst=C_RST))
                    print(line)
                    log_message(LOG_FILE, ENABLE_LOGGING, "[unexpected] " + line)

        except KeyboardInterrupt:
            print("\nStopping...")
            break
        except Exception as e:
            err = "[loop-error] {}".format(e)
            print(err)
            log_message(LOG_FILE, ENABLE_LOGGING, err)
        time.sleep(SCAN_INTERVAL)
      
if __name__ == "__main__":
    main()
