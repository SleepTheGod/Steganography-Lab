Steganography Lab

A PHP-based AES-256-CBC encrypted LSB steganography suite for encoding and decoding payloads in JPEG images. Designed for educational use in red team defense and cybersecurity labs, this project supports both CLI and web interfaces to simulate reverse shell scenarios safely.

Author: Taylor Christian Newsome
Version: 1.0.3
License: MIT (for educational use only; see LICENSE)

Features

AES-256-CBC Encryption: Securely encrypts payloads with a 32-byte key.
LSB Steganography: Embeds/decodes payloads in JPEG images using least significant bit (LSB) techniques.
CLI & Web Interfaces: Flexible usage via command line or browser-based UI.
Safe Payload Simulation: Simulates reverse shells, PowerShell, and Bash payloads without execution or network activity.
Logging: Decoded payloads are logged to logs/decoded.json with timestamps and OS metadata.
Base64-Encoded Examples: Includes safe, base64-encoded payloads for lab exercises.
OS Detection: Logs the operating system for SOC analysis.
Modular Design: Easy to extend for student labs and red team scenarios.
Simulated Features (No Real Execution)

Feature               Implementation
Reverse Shell         Simulated command string, logged locally
Remote Callback       Logged, no network activity
Payload Execution     Simulated with echo/log, not executed
Bash/PowerShell Chain Base64-encoded scripts, not run

Project Structure

Steganography-Lab/
stego_lab.php          Main script (CLI + web)
upload.html            Web front-end for student demos
logs/
decoded.json       Logs decoded payloads with timestamps
examples/
payload_base64.txt Example base64-encoded payloads
cover.jpg              Sample input image (not included)
output.jpg             Output image (generated)
README.md              This file

Prerequisites

PHP 7.4+ with GD, OpenSSL, and fileinfo extensions enabled.
A web server (e.g., Apache/NGINX) for web mode.
Write permissions for logs/ and the output directory.
A sample JPEG image (e.g., cover.jpg, 512x512 pixels recommended).
A safe lab environment (e.g., a VM with no network access).
Setup

Clone the repository: git clone https://github.com/SleepTheGod/Steganography-Lab.git cd Steganography-Lab
Create directories and set permissions: mkdir -p logs examples chmod -R 755 logs
Provide a sample JPEG (cover.jpg) in the project root.
(Optional) For web mode, place the project in a web server’s document root and ensure PHP is configured.
Usage

CLI Mode

Encode a payload: php stego_lab.php -m encode -i cover.jpg -o output.jpg -k 12345678901234567890123456789012 -p examples/payload_base64.txt Embeds the payload from examples/payload_base64.txt into output.jpg.
Decode a payload: php stego_lab.php -m decode -i output.jpg -k 12345678901234567890123456789012 Extracts the payload and logs it to logs/decoded.json.
View help: php stego_lab.php -h
Web Mode

Open upload.html in a browser (e.g., http://localhost/Steganography-Lab/upload.html).
Select Encode or Decode mode.
Upload a JPEG image (cover.jpg for encoding, output.jpg for decoding).
Enter a 32-byte AES key (default: LabEncryptionKey1234567890123456).
(For encoding) Paste a payload or leave blank for the default simulated payload.
Submit to process and download the output (for encoding) or view the decoded payload.
Example Log (logs/decoded.json)

{
"timestamp": "2025-06-21T16:15:00+00:00",
"decoded": "/* Simulated reverse shell for lab (disabled) / $host = '127.0.0.1'; $port = 4444; // $sock = fsockopen($host, $port); // while ($cmd = fgets($sock)) { //     $output = shell_exec($cmd); //     fwrite($sock, $output); // } / Simulated PowerShell payload (base64-encoded, not executed) / $ps = 'Write-Output "Simulated PowerShell payload"'; $ps_b64 = base64_encode($ps); / Simulated Bash payload (base64-encoded, not executed) */ $bash = 'echo "Simulated Bash payload"'; $bash_b64 = base64_encode($bash); echo "Shell payload logged for lab. PowerShell: $ps_b64, Bash: $bash_b64";",
"source": "output.jpg",
"os": "Linux"
}

Lab Safety Notes

Educational Use Only: This tool is for controlled lab environments. Do not use in production or unauthorized systems.
No Real Execution: Payloads are simulated and logged, not executed. Network activity is disabled.
Safe Environment: Run in a sandboxed VM with no network access to prevent accidental misuse.
Hardcoded Key: The default AES key (LabEncryptionKey1234567890123456) is for lab use only; use a secure key in real scenarios.
Example Lab Scenarios

Red Team Exercise
Encode a custom payload (e.g., whoami) into a JPEG.
Share the image and key with a teammate to decode and analyze.

SOC Analysis
Decode a provided output.jpg and review logs/decoded.json to identify the simulated payload.
Discuss detection strategies for steganography-based attacks.

Payload Testing
Modify examples/payload_base64.txt with new base64-encoded scripts (e.g., simulated keylogger output).
Test encoding/decoding and verify logs.
Contributing

Contributions are welcome! Please submit issues or pull requests for bug fixes, feature enhancements, or documentation improvements. Focus on maintaining educational safety and modularity.

Acknowledgments

Inspired by red team defense and steganography labs.
Built for cybersecurity students and educators.
Contact

For questions or feedback, open an issue on GitHub or contact SleepTheGod.
