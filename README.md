# 🕵️‍♂️ Steganography Lab

A **PHP-based AES-256-CBC encrypted LSB steganography suite** for encoding and decoding payloads in JPEG images.  
Designed for **educational red team defense and cybersecurity labs**, this project supports both CLI and web interfaces to **safely simulate reverse shell scenarios**.

**Author:** Taylor Christian Newsome  
**Version:** 1.0.3  
**License:** MIT *(Educational Use Only; See LICENSE)*

## 🚀 Features

- **AES-256-CBC Encryption** – Secure 32-byte key encryption  
- **LSB Steganography** – Embed and decode payloads in JPEG images  
- **CLI & Web Interfaces** – Use from terminal or browser  
- **Simulated Payloads** – Reverse shells, PowerShell, Bash (no execution or network activity)  
- **Auto Logging** – Decoded data saved to `logs/decoded.json` with OS info + timestamps  
- **Base64 Support** – Clean, safe payloads for classroom exercises  
- **OS Detection** – Logs host OS for blue team correlation  
- **Modular & Safe** – Easy to modify, safe for labs  

## 🧪 Simulated — Never Executed

| Feature               | Implementation Description                       |
|-----------------------|--------------------------------------------------|
| Reverse Shell         | Simulated as command string, never executed      |
| Remote Callback       | Placeholder-only, no external connection         |
| Payload Execution     | Simulated via echo/log only                      |
| Bash/PowerShell Chain | Base64-encoded scripts, no execution             |


## 📦 Requirements

- PHP 7.4+ with the following extensions: `gd`, `openssl`, `fileinfo`  
- Apache or NGINX (for web UI)  
- Write access to `logs/` and working directory  
- JPEG image (e.g., `cover.jpg`, ideally 512x512)  
- Offline lab or VM (no internet required)  

## 🛠️ Setup

```bash
git clone https://github.com/SleepTheGod/Steganography-Lab.git
cd Steganography-Lab
mkdir -p logs examples
chmod -R 755 logs
# Place a valid JPEG as cover.jpg in the project root
```
💻 CLI Usage
➕ Encode a Payload
```bash
php stego_lab.php -m encode -i cover.jpg -o output.jpg -k 12345678901234567890123456789012 -p examples/payload_base64.txt
```
Embeds the payload into output.jpg using AES-256-CBC.

🔍 Decode a Payload
```bash
php stego_lab.php -m decode -i output.jpg -k 12345678901234567890123456789012
```
Extracts and logs decoded payloads to logs/decoded.json.

📖 Help Menu
```bash
php stego_lab.php -h
```
🌐 Web Interface
Open upload.html in a browser
(e.g., http://localhost/Steganography-Lab/upload.html)

Choose Encode or Decode

Upload JPEG (cover.jpg or output.jpg)

Enter 32-byte AES key
(Default: LabEncryptionKey1234567890123456)

(Encode only) Paste a base64 payload or use default

Submit to generate output or view decoded data

📋 Example Log – logs/decoded.json
```json
{
  "timestamp": "2025-06-21T16:15:00+00:00",
  "decoded": "/* Simulated reverse shell for lab (disabled) */ $host = '127.0.0.1'; $port = 4444; /* Simulated PowerShell payload (base64-encoded, not executed) */ $ps = 'Write-Output \"Simulated PowerShell payload\"'; $ps_b64 = base64_encode($ps); /* Simulated Bash payload (base64-encoded, not executed) */ $bash = 'echo \"Simulated Bash payload\"'; $bash_b64 = base64_encode($bash); echo \"Shell payload logged for lab. PowerShell: $ps_b64, Bash: $bash_b64\";",
  "source": "output.jpg",
  "os": "Linux"
}
```
🔐 Safety Guidelines
🧪 Educational Use Only – Designed for red team/soc lab simulations

⚠️ No Execution – Code simulates payloads only; no network, no shell

🧱 Isolated Environment – Use in virtual machines without internet access

🔑 Default Key Warning – Change the default AES key before real use

🎯 Example Lab Scenarios
1. Red Team Exercise
Encode a payload like whoami into cover.jpg

Share the image + key with another student to decode + analyze

2. Blue Team / SOC Analysis
Receive output.jpg, decode it

Inspect logs/decoded.json, identify payload signatures

3. Payload Modification
Add new base64 commands to examples/payload_base64.txt

Encode → Decode → Log → Inspect

🤝 Contributing
Contributions are welcome!
Please submit issues or PRs for:

Bugs

Educational feature requests

Documentation improvements

Ensure contributions preserve safety, modularity, and non-execution guarantees.

🏆 Acknowledgments
Inspired by red team/blue team CTFs and lab environments

Built for students, instructors, and security researchers

📫 Contact
Questions? Feedback?
Open an issue or contact SleepTheGod

