# rune
RUNE - RDP User NLA Exposed 

RUNE (RDP User NLA Exposed) is an advanced Python-based tool designed to detect exposed usernames on RDP services that have Network Level Authentication (NLA) disabled.

By leveraging rdesktop and OCR techniques, RUNE connects to remote desktop endpoints and extracts visible usernames from the login screen, providing a valuable asset for red teaming, vulnerability assessments, and exposure auditing.

Features:
    Detect RDP endpoints with NLA disabled
    Extract and list exposed usernames from login screen
    OCR-based parsing of screen content
    Auto-retry on black/empty screenshots
    Filters out default system messages and certificate info
    Outputs results grouped by IP and hostname
    
Usage:

    python3 rune.py <target-ip-range>

Results are saved and printed in a clean format, showing discovered usernames and other useful metadata.

RUNE makes use of several powerful open-source tools to perform its tasks. These tools are essential for scanning, connecting, capturing, and extracting information from RDP services. If they are not installed on your system, the script will automatically attempt to install them for you.

Special thanks to the following projects:

   rdesktop – Used to initiate RDP connections to servers without Network Level Authentication.
   
   Tesseract OCR – For performing optical character recognition on captured login screens.
   
   ImageMagick – Utilized for image conversion and analysis (convert, identify).
   
   Xvfb (X virtual framebuffer) – Enables headless graphical session management.
   
   x11-utils (xdpyinfo) – Provides utilities to inspect X display properties.

These tools are critical for RUNE’s functionality, and full credit goes to their maintainers and open-source contributors.

Disclaimer:

This tool is intended for ethical and authorized security assessments only. Unauthorized use against systems you do not own or have permission to test is strictly prohibited.

<img width="592" height="370" alt="1" src="https://github.com/user-attachments/assets/66433f05-2f85-44fb-a73e-d6bc66f4d3d7" />

<img width="684" height="317" alt="2" src="https://github.com/user-attachments/assets/51d08481-2201-4a9a-84c7-653904583839" />
