#!/usr/bin/env python3
"""
rune.py – RUNE (RDP Username NLA Exposed)
Headless discovery of RDP endpoints without NLA, with OCR username extraction.
2025‑07‑19
"""

from __future__ import annotations
import argparse
import ipaddress
import re
import select
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Tuple

# ──────────────────────── helpers ─────────────────────────
def run(cmd: List[str], *, input_text: str | None = None,
        timeout: int | None = None, env: dict | None = None) -> Tuple[int, str, str]:
    """Simplified subprocess wrapper that captures stdout and stderr."""
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE if input_text else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )
    try:
        out, err = proc.communicate(input=input_text, timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        return 1, "", "Command timed out"
    return proc.returncode, out, err

which = shutil.which

# ───────────────────── colour output ─────────────────────
def _setup_colour():
    global ok, warn, err, info
    try:
        from colorama import Fore, Style, init as cinit
    except ImportError:
        print("[i] Installing ‘colorama’ …")
        c, _, e = run([sys.executable, "-m", "pip", "install", "--user", "colorama"])
        if c:
            print("[!] pip failed:", e.strip())
        from colorama import Fore, Style, init as cinit
    cinit()
    G, R, Y, C, END = Fore.GREEN, Fore.RED, Fore.YELLOW, Fore.CYAN, Style.RESET_ALL
    ok   = lambda s: f"{G}{s}{END}"
    warn = lambda s: f"{Y}{s}{END}"
    err  = lambda s: f"{R}{s}{END}"
    info = lambda s: f"{C}{s}{END}"
_setup_colour()

# ───────────────── dependency check ──────────────────────
REQUIRED_TOOLS = {
    "nmap":      "nmap",
    "rdesktop":  "rdesktop",
    "tesseract": "tesseract-ocr",
    "convert":   "imagemagick",
    "identify":  "imagemagick",
    "xvfb-run":  "xvfb",
    "xdpyinfo":  "x11-utils",
}
def ensure_deps(auto_yes=False):
    missing = [pkg for bin_, pkg in REQUIRED_TOOLS.items() if not which(bin_)]
    if not missing:
        return
    print(err("Missing tools: ") + ", ".join(missing))
    if not auto_yes and input("Install with apt? [y/N]: ").strip().lower() != "y":
        sys.exit(err("Aborted."))
    cmd = "sudo apt-get update && sudo apt-get install -y " + " ".join(missing)
    c, _, e = run(["bash", "-c", cmd])
    if c:
        sys.exit(err(e.strip()))

# ──────────────────── image helpers ─────────────────────
def is_black(img: Path,
             mean_thresh: float = 0.04,
             low_mean: float = 0.10,
             std_thresh: float = 0.02) -> bool:
    """
    A frame is considered "black" (blank) when:
      • mean brightness is very low, OR
      • mean is moderately low *and* the image lacks contrast (very low stdev).
    This heuristic reliably flags uniformly dark‑grey frames that slipped
    through the previous single‑threshold check.
    """
    c, out, _ = run(
        ["identify", "-format", "%[fx:mean] %[fx:standard_deviation]", str(img)]
    )
    try:
        mean, std = (float(x) for x in out.strip().split())
    except Exception:
        return False  # fallback: assume not black if metrics missing
    if mean < mean_thresh:
        return True
    if mean < low_mean and std < std_thresh:
        return True
    return False

def enhance(src: Path, dst: Path):
    run([
        "convert", str(src),
        "-grayscale", "Rec709Luminance",
        "-resample",  "300x300",
        "-unsharp",   "6.8x2.69",
        "-quality",   "100", str(dst)
    ])

# ──────────────── rdesktop capture logic ───────────────
VALIDATE_WAIT = 10   # seconds after answering 'yes' to check log
SCREEN_WAIT   = 10   # total wait before screenshot
def _capture_once(host: str, shot: Path) -> str:
    """
    Run rdesktop headlessly, feed 'yes', wait, screenshot, return log text.
    """
    inner = (
        f"printf 'yes\\n' | rdesktop -x m -z -a 16 -u '' {host} & "
        "pid=$!; "
        f"sleep {SCREEN_WAIT}; "
        f"import -display $DISPLAY -window root {shot} >/dev/null 2>&1; "
        "kill -TERM $pid 2>/dev/null; wait $pid 2>/dev/null || true"
    )
    cmd = ["xvfb-run", "-a", "-s", "-screen 0 1024x768x24", "bash", "-c", inner]
    _, o, e = run(cmd, timeout=SCREEN_WAIT + 30)
    return o + e

def parse_machine_name(log: str) -> str:
    for ln in log.splitlines():
        m = re.search(r"Subject:.*?CN=([^,]+)", ln, re.I)
        if m:
            return m.group(1).strip()
    return "unknown"

def headless_rdesktop(
    host: str, shot: Path, attempts: int = 3
) -> Tuple[bool, str]:
    """
    Returns (vulnerable_no_NLA, full_log).
    Considers the host vulnerable if either:
      • 'Connection established' appears, or
      • a non‑black screenshot is captured.
    """
    nla_re = re.compile(
        r"(Network Level Authentication|Protocol security negotiation failed)", re.I
    )
    for attempt in range(1, attempts + 1):
        if shot.exists():
            shot.unlink()

        log = _capture_once(host, shot)

        # Explicit NLA failure?
        if nla_re.search(log):
            return False, log

        established = "Connection established" in log
        good_image  = shot.exists() and not is_black(shot)
        if established or good_image:
            return True, log  # No NLA

        if attempt < attempts:
            print(warn(f"[i] Black frame — retry {attempt}/{attempts - 1} …"))

    return False, log  # After retries, assume NLA enabled

# ──────────────────── OCR helper ──────────────────────
IGNORE = {
    "cancel","just","login","connecting","password","kennwort",
    "eng","username","xorg","0000","session","already","defined","alredeady",
    "definded","xvnc","passwort","windows","signed","in","pc","settings",
    "install","them","r2","go","to","2012","server","important","update",
    "are","available","updates","please","for","the","wait"
}
TOK_RE = re.compile(r"[A-Za-z0-9_.-]{3,}")

def ocr(img: Path) -> List[str]:
    c, out, _ = run(["tesseract", str(img), "stdout"])
    if c:
        return []
    names = set()
    for tok in TOK_RE.findall(out):
        if tok.lower() in IGNORE:
            continue
        names.add(tok)
    return sorted(names)

# ───────────────────── nmap scanner ───────────────────
BAR_LEN = 40
def scan(target: str, dbg=False) -> List[str]:
    print(info(f"[*] Scanning {target} …"))
    cmd = [
        "nmap", "-p", "3389", "--open", "-n", "-Pn",
        "--stats-every", "2s",
        "-oG", "-", target
    ]
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )

    out_lines: List[str] = []
    percent = 0.0
    spinner = "|/-\\"
    spin_idx = 0

    # Use select to read both stdout and stderr without blocking
    while True:
        reads = [proc.stderr]
        if proc.stdout:
            reads.append(proc.stdout)
        rlist, _, _ = select.select(reads, [], [], 0.2)

        for pipe in rlist:
            line = pipe.readline()
            if not line:
                continue
            if pipe is proc.stderr:
                m = re.search(r"About\s+([0-9.]+)%\s+done", line)
                if m:
                    percent = float(m.group(1))
                    filled = int(percent / 100 * BAR_LEN)
                    bar = "#" * filled + "-" * (BAR_LEN - filled)
                    sys.stdout.write(
                        f"\rScanning {target}: [{bar}] {percent:5.1f}%"
                    )
                    sys.stdout.flush()
            else:  # stdout
                if dbg:
                    print(line, end="")
                out_lines.append(line)

        if proc.poll() is not None:
            break  # process ended

        if not rlist:  # idle, show spinner when no percent yet
            if percent == 0.0:
                sys.stdout.write(
                    f"\rScanning {target} {spinner[spin_idx]}"
                )
                sys.stdout.flush()
                spin_idx = (spin_idx + 1) % len(spinner)

    # Finish reading remaining stdout
    remaining_out, _ = proc.communicate()
    if remaining_out:
        out_lines.append(remaining_out)
        if dbg:
            print(remaining_out, end="")

    sys.stdout.write("\r")  # clear progress line
    sys.stdout.flush()

    # Parse hosts with port 3389 open
    hosts: List[str] = []
    for line in "".join(out_lines).splitlines():
        if "3389/open" not in line:
            continue
        m = re.search(r"Host:\s+([0-9A-Fa-f:.]+)", line)
        if m:
            hosts.append(m.group(1))

    print(ok(f"[+] {len(hosts)} host(s) with 3389 open"))
    return hosts

# ───────────────────────── main ───────────────────────
def main():
    print(ok("RUNE (RDP Username NLA Exposed)\n"))

    ap = argparse.ArgumentParser(description="Headless RDP scanner with OCR")
    ap.add_argument("target")
    ap.add_argument("-o", "--out", default="output")
    ap.add_argument("-y", "--yes", action="store_true",
                    help="auto-install missing dependencies")
    ap.add_argument("--debug", action="store_true",
                    help="print raw nmap output in real time")
    args = ap.parse_args()

    ensure_deps(args.yes)

    root = Path(args.out).expanduser().resolve()
    raw_dir  = root / "raw"
    enh_dir  = root / "enhanced"
    raw_dir.mkdir(parents=True, exist_ok=True)
    enh_dir.mkdir(exist_ok=True)

    results = []           # (ip, machine, vulnerable, usernames)
    vulnerable_ips = []

    for ip in scan(args.target, args.debug):
        screenshot = raw_dir / f"{ip}.png"
        print(info(f"[*] Connecting {ip}"))

        vulnerable, log = headless_rdesktop(ip, screenshot)
        machine_name = parse_machine_name(log)

        if vulnerable:
            print(err(f"[!] {ip} VULNERABLE (NLA disabled)"))
            usernames: List[str] = []
            if screenshot.exists():
                enhanced = enh_dir / screenshot.name
                enhance(screenshot, enhanced)
                usernames = ocr(enhanced)
            vulnerable_ips.append(ip)
        else:
            print(warn(f"[-] {ip} Port open but NLA enabled"))
            usernames = []

        results.append((ip, machine_name, vulnerable, usernames))

    # ────────────── formatted summary ──────────────
    print(ok("\n===== RESULTS ====="))
    for ip, machine, vul, names in results:
        header = f"{ip} ({machine}) {'[VULNERABLE]' if vul else '[NLA Enabled]'}"
        print((err if vul else warn)(header))
        for name in names:
            print(f"  - {name}")

    if vulnerable_ips:
        print(err("\n===== VULNERABLE HOSTS ====="))
        for v in vulnerable_ips:
            print(" *", v)
    else:
        print(ok("\n[*] No vulnerable RDP endpoints detected"))

    # User‑requested closing note
    print(info(
        "\nIn the RAW folder you will find an image of each device for potential manual inspection."
    ))

    # ──────────── cleanup enhanced dir ─────────────
    shutil.rmtree(enh_dir, ignore_errors=True)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(err("\n[!] Interrupted"))
