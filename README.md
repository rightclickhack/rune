# RUNE (Remote Desktop Unauthenticated Network Enumerator)
Version 0.9 

<img width="805" height="542" alt="4" src="https://github.com/user-attachments/assets/921d03c9-c164-4080-8954-756ac51c95ad" />

RUNE is a specialized offensive security and auditing tool designed to evaluate Windows Remote Desktop Protocol (RDP) environments. It automates the discovery of RDP services with Network Level Authentication (NLA) disabled, capturing and analyzing exposed login screens to extract actionable intelligence during penetration testing, red team engagements, or routine security audits.

🚀 Key Features

Automated NLA Bypass Detection: Scans networks for port 3389 and identifies RDP servers that allow connections without prior Network Level Authentication.

Headless Screen Capture: Establishes a stealthy, headless RDP session (using Xvfb and rdesktop) to interact with the target and capture the Windows logon screen without spawning visible windows.

OCR Username Extraction: Automatically crops, filters, and enhances the captured screenshots using ImageMagick, then processes them through Tesseract OCR to extract exposed usernames while intelligently filtering out common OS text (e.g., "Administrator", "Password", "Settings").

Computer Vision UI Analysis: Employs OpenCV template matching to detect interactive elements on the lock screen. It features spatial validation to accurately distinguish between the Power icon and the Accessibility icon.

NTLM Domain Enumeration: When executed with the full scan flag (-f), it leverages Nmap scripts to extract hostname, domain structure, and OS version details from the target.

Auto-Dependency Resolution: Built-in routine to automatically identify and install missing system binaries (via apt) and Python libraries.

🛠️ Prerequisites

RUNE requires a Linux environment (preferably Debian/Ubuntu-based like Kali Linux or Parrot OS). The script includes an auto-installer feature, but the underlying dependencies are:

System Binaries:

    nmap

    rdesktop

    tesseract-ocr

    imagemagick

    xvfb

    xterm

Python 3 Libraries:

    colorama

    opencv-python (cv2)

    numpy

# Usage

Run the script with Python 3 and provide a target IP or CIDR range.
Bash

Basic scan
python3 rune_v2.py 192.168.1.0/24

Auto-accept dependency installation
python3 rune_v2.py 192.168.1.0/24 -y

Full scan (Includes NTLM info enumeration)
python3 rune_v2.py 192.168.1.0/24 -f

Specify a custom output directory
python3 rune_v2.py 192.168.1.0/24 -o /path/to/custom/folder


⚠️ Disclaimer

Legal Usage: This tool is intended strictly for authorized security auditing, academic research, and lawful penetration testing. Do not use this tool against networks or systems for which you do not have explicit, written permission.

Accuracy: This program is based on OCR (Optical Character Recognition). Always double-check the screenshots in the output folder to manually confirm the results and usernames extracted.




