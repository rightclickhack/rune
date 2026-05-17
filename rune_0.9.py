#!/usr/bin/env python3

from __future__ import annotations
import argparse
import base64
import importlib.util
import itertools
import os
import queue
import random
import re
import select
import shutil
import subprocess
import sys
import termios
import threading
import time
import tty
from pathlib import Path
from typing import List, Tuple

# Reemplaza estos strings con el base64 real de tus imágenes
POWER_TEMPLATE_B64 = b"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"
ACCESS_TEMPLATE_B64 = b"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"

def run(cmd: List[str], *, input_text: str | None = None,
        timeout: int | None = None, env: dict | None = None) -> Tuple[int, str, str]:
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

def get_single_char_timeout(timeout_sec: int) -> str | None:
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(sys.stdin.fileno())
        rlist, _, _ = select.select([sys.stdin], [], [], timeout_sec)
        if rlist:
            ch = sys.stdin.read(1)
            return ch
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    return None

def ensure_deps(auto_yes=False):
    missing_apt = []
    binaries = {
        "nmap": "nmap", "rdesktop": "rdesktop", "tesseract": "tesseract-ocr",
        "convert": "imagemagick", "import": "imagemagick", "identify": "imagemagick",
        "Xvfb": "xvfb", "xterm": "xterm"
    }
    for bin_name, apt_name in binaries.items():
        if not shutil.which(bin_name):
            if apt_name not in missing_apt: missing_apt.append(apt_name)

    python_modules = {"colorama": "python3-colorama", "cv2": "python3-opencv", "numpy": "python3-numpy"}
    for mod_name, apt_name in python_modules.items():
        if importlib.util.find_spec(mod_name) is None:
            if apt_name not in missing_apt: missing_apt.append(apt_name)

    if missing_apt:
        print(f"[!] Missing dependencies: {', '.join(missing_apt)}")
        if not auto_yes and input("Install with apt? [y/N]: ").strip().lower() != "y":
            sys.exit("[-] Aborted.")
        print("[i] Installing packages via apt. Please wait...")
        code, out, err = run(["bash", "-c", "sudo apt-get update && sudo apt-get install -y " + " ".join(missing_apt)])
        if code != 0: sys.exit(f"[-] Failed to install dependencies:\n{err}")
        print("[i] Dependencies installed. Restarting script...")
        os.execv(sys.executable, [sys.executable] + sys.argv)

def setup_colour():
    global ok, warn, err, info
    from colorama import Fore, Style, init as cinit
    cinit()
    G, R, Y, C, END = Fore.GREEN, Fore.RED, Fore.YELLOW, Fore.CYAN, Style.RESET_ALL
    ok   = lambda s: f"{G}{s}{END}"
    warn = lambda s: f"{Y}{s}{END}"
    err  = lambda s: f"{R}{s}{END}"
    info = lambda s: f"{C}{s}{END}"

class Spinner:
    def __init__(self, message="Processing..."):
        self.spinner = itertools.cycle(['-', '\\', '|', '/'])
        self.delay = 0.1
        self.busy = False
        self.paused = False
        self.message = message
        self.thread = None

    def spin(self):
        while self.busy:
            if not self.paused:
                sys.stdout.write(f"\r{info('[~]')} {self.message} {info(next(self.spinner))}")
                sys.stdout.flush()
            time.sleep(self.delay)

    def pause(self):
        self.paused = True
        sys.stdout.write(f"\r{' ' * 100}\r")
        sys.stdout.flush()

    def resume(self):
        self.paused = False

    def __enter__(self):
        self.busy = True
        self.thread = threading.Thread(target=self.spin)
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.busy = False
        time.sleep(self.delay)
        if self.thread is not None: self.thread.join()
        sys.stdout.write("\r" + " " * (len(self.message) + 15) + "\r")
        sys.stdout.flush()

class VirtualDisplay:
    def __init__(self):
        self.display = f":{random.randint(100, 999)}"
        self.proc = None
        
    def __enter__(self):
        self.proc = subprocess.Popen(
            ["Xvfb", self.display, "-screen", "0", "1024x768x24"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        time.sleep(0.5) 
        return self.display
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.proc:
            self.proc.terminate()
            self.proc.wait()

def is_unrendered(img: Path) -> bool:
    code, out, _ = run(["identify", "-format", "%[fx:mean] %[fx:standard_deviation]", str(img)])
    try:
        mean, std = (float(x) for x in out.strip().split())
        if std < 0.02 or mean < 0.02:
            return True
    except Exception:
        pass
    return False

def enhance(src: Path, dst: Path):
    run(["convert", str(src), "-gravity", "South", "-chop", "0x120", "-grayscale", "Rec709Luminance",
         "-resample", "300x300", "-unsharp", "6.8x2.69", "-quality", "100", str(dst)])

def detect_power_icon(img_path: Path, power_path: str, access_path: str) -> bool:
    if not Path(power_path).exists() or not Path(access_path).exists(): 
        return False
        
    import cv2
    import numpy as np
    
    try:
        img = cv2.imread(str(img_path), cv2.IMREAD_GRAYSCALE)
        template_p = cv2.imread(str(power_path), cv2.IMREAD_GRAYSCALE)
        template_a = cv2.imread(str(access_path), cv2.IMREAD_GRAYSCALE)
        
        if img is None or template_p is None or template_a is None: 
            return False
        
        height, width = img.shape
        roi = img[int(height*0.65):height, int(width*0.65):width]
        
        tp_h, tp_w = template_p.shape
        ta_h, ta_w = template_a.shape
        
        for scale in np.linspace(0.5, 1.5, 15)[::-1]:
            resized_power = cv2.resize(template_p, (int(tp_w * scale), int(tp_h * scale)))
            resized_access = cv2.resize(template_a, (int(ta_w * scale), int(ta_h * scale)))
            
            if resized_power.shape[0] > roi.shape[0] or resized_power.shape[1] > roi.shape[1]:
                continue
                
            res_power = cv2.matchTemplate(roi, resized_power, cv2.TM_CCOEFF_NORMED)
            _, max_val_p, _, _ = cv2.minMaxLoc(res_power)
            
            if max_val_p >= 0.75:
                res_access = cv2.matchTemplate(roi, resized_access, cv2.TM_CCOEFF_NORMED)
                _, max_val_a, _, _ = cv2.minMaxLoc(res_access)
                
                if max_val_a > max_val_p:
                    continue 
                
                return True 
        return False
    except Exception:
        return False

def get_ntlm_info(ip: str) -> List[str]:
    cmd = ["nmap", "-p", "3389", "-Pn", "-n", "--script", "rdp-ntlm-info", ip]
    code, out, err = run(cmd)
    results = []
    in_script = False
    for line in out.splitlines():
        if "rdp-ntlm-info:" in line:
            in_script = True
            continue
        if in_script:
            if line.strip().startswith("|"):
                clean_line = line.replace("|_", "").replace("|", "").strip()
                if clean_line: results.append(clean_line)
            elif not line.strip() or "Nmap done" in line:
                break
    return results

def headless_rdesktop(host: str, shot: Path, spinner: Spinner, main_env: dict) -> Tuple[bool, str, bool, bool]:
    is_blank_screen = True
    manual_review = False
    log_out = ""
    cmd = ["rdesktop", "-u", "", "-g", "1024x768", host]
    
    with VirtualDisplay() as disp1:
        env1 = main_env.copy()
        env1["DISPLAY"] = disp1
        
        rdp_proc1 = subprocess.Popen(
            cmd, 
            stdin=subprocess.PIPE, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.STDOUT, 
            text=True, 
            env=env1
        )
        
        try:
            rdp_proc1.stdin.write("yes\n")
            rdp_proc1.stdin.flush()
        except Exception:
            pass 
            
        try:
            rdp_proc1.wait(timeout=20)
        except subprocess.TimeoutExpired:
            pass 
            
        subprocess.run(["import", "-window", "root", str(shot)], env=env1, stderr=subprocess.DEVNULL)
        is_blank_screen = not shot.exists() or is_unrendered(shot)
        
        rdp_proc1.terminate()
        out1, _ = rdp_proc1.communicate()
        log_out += (out1 or "")

    if is_blank_screen and "Connection established" in log_out:
        spinner.pause()
        print(warn(f"\n[!] Hidden capture failed (Blank Screen). Forcing a new visible terminal window for 10 seconds..."))
        spinner.resume()
        
        if "DISPLAY" not in main_env:
            main_env["DISPLAY"] = ":0"
            
        cmd_visible = [
            "xterm", "-title", f"RUNE Testing: {host}", 
            "-e", "bash", "-c", f"echo yes | rdesktop -u '' -g 1024x768 {host}"
        ]
        
        rdp_proc2 = subprocess.Popen(cmd_visible, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=main_env)
        time.sleep(20)
        subprocess.run(["import", "-window", "root", str(shot)], env=main_env, stderr=subprocess.DEVNULL)
        is_blank_screen = not shot.exists() or is_unrendered(shot)
            
        rdp_proc2.terminate()
        log_out2, _ = rdp_proc2.communicate()
        log_out += "\n" + (log_out2 or "")
        
        if is_blank_screen:
            spinner.pause()
            print(err(f"[-] Visible test failed. Screen is still blank after 10s. Proceeding..."))
            manual_review = True
            spinner.resume()

    nla_re = re.compile(r"(Network Level Authentication|Protocol security negotiation failed)", re.I)
    if nla_re.search(log_out):
        return False, log_out, False, False
        
    vulnerable = "Connection established" in log_out or (shot.exists() and not is_blank_screen)
    if is_blank_screen and "Connection established" in log_out:
        vulnerable = True 
        
    return vulnerable, log_out, is_blank_screen, manual_review

def parse_machine_name(log: str) -> str:
    for ln in log.splitlines():
        m = re.search(r"Subject:.*?CN=([^,]+)", ln, re.I)
        if m: return m.group(1).strip()
    return "unknown"

OTHER_USER_WORDS = {
    "other", "otro", "autre", "andere", "altro", "outro", "drugoi", "drugoy", 
    "inny", "ander", "diger", "druhý", "muut", "mas"
}

def ocr(img: Path) -> Tuple[List[str], bool]:
    IGNORE = {
        "cancel","just","login","connecting","password","kennwort","eng","username","xorg","0000",
        "session","already","defined","alredeady","definded","xvnc","passwort","windows","signed",
        "in","pc","settings","install","them","r2","go","to","2012","server","important","update",
        "are","available","updates","please","for","the","wait","2008","2016","2019","2022",
        "datacenter","standard","evaluation","edition","user","domain","how","do","i",
        "sign","another","myfishbowl","ease","access","power","shut","down","restart","sswora","ssword","sleep","options"
    }
    c, out, _ = run(["tesseract", str(img), "stdout"])
    if c: return [], False
    
    raw_tokens = re.findall(r"[A-Za-z0-9_.-]{3,}", out)
    has_other_user = any(t.lower() in OTHER_USER_WORDS for t in raw_tokens)
    
    clean_names = sorted({tok for tok in raw_tokens if tok.lower() not in IGNORE and tok.lower() not in OTHER_USER_WORDS})
    return clean_names, has_other_user

def nmap_worker(target: str, ip_queue: queue.Queue):
    cmd = ["nmap", "-p", "3389", "--open", "-n", "-Pn", "-oG", "-", target]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    
    for line in iter(proc.stdout.readline, ''):
        if "3389/open" in line:
            m = re.search(r"Host:\s+([0-9A-Fa-f:.]+)", line)
            if m: ip_queue.put(m.group(1))
            
    proc.wait()
    ip_queue.put(None)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("-o", "--out", default="output")
    ap.add_argument("-y", "--yes", action="store_true")
    ap.add_argument("-f", "--full", action="store_true")
    args = ap.parse_args()

    ensure_deps(args.yes)
    setup_colour()
    
    print(ok(r"""
  _____   _    _  _   _  ______ 
 |  __ \ | |  | || \ | ||  ____|
 | |__) || |  | ||  \| || |__   
 |  _  / | |  | || . ` ||  __|  
 | | \ \ | |__| || |\  || |____ 
 |_|  \_\ \____/ |_| \_||______|
    """))
    print(info("               Version 0.9"))
    print(info("        Developed by Guillermo Pineda\n"))
    print(warn(" [!] Note: OCR detection don't forget to check the output folder.\n"))

    root = Path(args.out).expanduser().resolve()
    raw_dir, enh_dir  = root / "raw", root / "enhanced"
    raw_dir.mkdir(parents=True, exist_ok=True)
    enh_dir.mkdir(exist_ok=True)

    power_path = root / "power_template.png"
    access_path = root / "access_template.png"
    
    try:
        with open(power_path, "wb") as f:
            f.write(base64.b64decode(POWER_TEMPLATE_B64))
        with open(access_path, "wb") as f:
            f.write(base64.b64decode(ACCESS_TEMPLATE_B64))
    except Exception as e:
        print(err(f"[-] Error writing base64 templates: {e}"))

    main_env = os.environ.copy()
    ip_queue = queue.Queue()
    nmap_thread = threading.Thread(target=nmap_worker, args=(args.target, ip_queue), daemon=True)
    nmap_thread.start()
    
    print(info(f"[*] Initiating network sweep on {args.target}... Waiting for first host...\n"))

    while True:
        ip = ip_queue.get()
        if ip is None: 
            break
            
        screenshot = raw_dir / f"{ip}.png"
        
        with Spinner(f"Open port found! Analyzing RDP environment on {ip}...") as spinner:
            vulnerable, log, is_blank_screen, manual_review = headless_rdesktop(ip, screenshot, spinner, main_env)
            machine_name = parse_machine_name(log)
            
            ntlm_data = []
            if args.full:
                ntlm_data = get_ntlm_info(ip)

        if vulnerable:
            if manual_review:
                print(warn(f"[!] {ip} ({machine_name}) VULNERABLE (NLA disabled) - {info('[BLANK SCREEN - Manual review required]')}\n"))
            else:
                has_power = False
                usernames = []
                has_other_user = False
                
                if screenshot.exists():
                    has_power = detect_power_icon(screenshot, str(power_path), str(access_path))
                    enhanced = enh_dir / screenshot.name
                    enhance(screenshot, enhanced)
                    usernames, has_other_user = ocr(enhanced)

                if has_other_user and not usernames:
                    print(err(f"[!] {ip} ({machine_name}) VULNERABLE (NLA disabled) - {warn('No active users (Login screen)')}"))
                else:
                    print(err(f"[!] {ip} ({machine_name}) VULNERABLE (NLA disabled)"))
                
                for name in usernames: 
                    print(f"  - Discovered User: {name}")
                if has_power:
                    print(warn("  -> [Interactive UI: Power Icon detected in Bottom-Right]"))
                print("") 
                    
        else:
            print(warn(f"[-] {ip} ({machine_name}) Port open but NLA enabled\n"))

        if ntlm_data:
            print(info("  |--[ Network NTLM Info ]--"))
            for line in ntlm_data:
                print(info(f"  |  {line}"))
            print("") 

    print(ok("[+] Network sweep and analysis complete."))
    shutil.rmtree(enh_dir, ignore_errors=True)

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: sys.exit(err("\n[!] Interrupted by user"))
