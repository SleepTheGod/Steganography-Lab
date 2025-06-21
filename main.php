<?php
/**
 * Taylor Christian Newsome PHP Steg Lab Version 1.0.3
 * AES Encrypted LSB Steganography Suite (Encode/Decode)
 * For educational use in red team defense and stego labs.
 * Supports CLI and web interfaces.
 */

// ========= CONFIG =========
define("STEGO_VERSION", "Taylor Christian Newsome PHP Steg Lab Version 1.0.3");
define("DEFAULT_COVER", "cover.jpg");
define("DEFAULT_OUTPUT", "output.jpg");
define("DEFAULT_LOG", "logs/decoded.json");
define("DEFAULT_AES_KEY", "LabEncryptionKey1234567890123456"); // 32 bytes for AES-256
define("TERMINATOR", "END_STEG"); // Custom terminator for reliability
define("PAYLOAD_DIR", "examples/payload_base64.txt");

// ========= INIT =========
// Detect execution mode (CLI or web)
$isCli = php_sapi_name() === 'cli';
if ($isCli) {
    echo STEGO_VERSION . "\n";
    $options = getopt("m:i:o:k:p:h", ["mode:", "input:", "output:", "key:", "payload:", "help"]);
    if (isset($options['h']) || isset($options['help'])) {
        echo "\nUsage (CLI):\n";
        echo "  php stego_lab.php -m encode -i cover.jpg -o output.jpg -k YourAESKey32Bytes -p payload.txt\n";
        echo "  php stego_lab.php -m decode -i output.jpg -k YourAESKey32Bytes\n";
        exit(0);
    }
    $mode = $options['m'] ?? $options['mode'] ?? 'encode';
    $input = $options['i'] ?? $options['input'] ?? DEFAULT_COVER;
    $output = $options['o'] ?? $options['output'] ?? DEFAULT_OUTPUT;
    $key = $options['k'] ?? $options['key'] ?? DEFAULT_AES_KEY;
    $payloadFile = $options['p'] ?? $options['payload'] ?? PAYLOAD_DIR;
} else {
    // Web mode
    header('Content-Type: text/html');
    $mode = $_POST['mode'] ?? 'encode';
    $key = $_POST['key'] ?? DEFAULT_AES_KEY;
    $payload = $_POST['payload'] ?? '';
    $input = $_FILES['input']['tmp_name'] ?? DEFAULT_COVER;
    $output = DEFAULT_OUTPUT;
    if (isset($_POST['download']) && file_exists(DEFAULT_OUTPUT)) {
        header('Content-Type: image/jpeg');
        header('Content-Disposition: attachment; filename="' . basename(DEFAULT_OUTPUT) . '"');
        readfile(DEFAULT_OUTPUT);
        exit;
    }
}

// Validate inputs
if (!file_exists($input) || !is_readable($input) || !isJpegFile($input)) {
    dieMessage("Input file '$input' is invalid or not a JPEG.", $isCli);
}
if ($mode === 'encode' && !is_writable(dirname($output))) {
    dieMessage("Output directory for '$output' is not writable.", $isCli);
}
if (strlen($key) !== 32) {
    dieMessage("AES key must be exactly 32 bytes.", $isCli);
}

// ========= FUNCTIONS =========
function isJpegFile($file) {
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mime = finfo_file($finfo, $file);
    finfo_close($finfo);
    return $mime === 'image/jpeg';
}

function dieMessage($message, $isCli) {
    $prefix = $isCli ? "❌ Error: " : "<p style='color:red'>Error: ";
    $suffix = $isCli ? "\n" : "</p>";
    die($prefix . $message . $suffix);
}

function encryptMessage($message, $key) {
    $iv = openssl_random_pseudo_bytes(16);
    $cipher = openssl_encrypt($message, 'aes-256-cbc', $key, 0, $iv);
    if ($cipher === false) {
        die("❌ Encryption failed.");
    }
    return base64_encode($iv . $cipher);
}

function decryptMessage($b64data, $key) {
    $raw = base64_decode($b64data, true);
    if ($raw === false) {
        die("❌ Invalid base64 data.");
    }
    $iv = substr($raw, 0, 16);
    $cipher = substr($raw, 16);
    $decrypted = openssl_decrypt($cipher, 'aes-256-cbc', $key, 0, $iv);
    if ($decrypted === false) {
        die("❌ Decryption failed.");
    }
    return $decrypted;
}

function embedMessage($imagePath, $outPath, $message, $terminator) {
    $img = @imagecreatefromjpeg($imagePath);
    if (!$img) dieMessage("Error loading image.", php_sapi_name() === 'cli');

    $width = imagesx($img);
    $height = imagesy($img);
    $pixels = $width * $height;

    $message .= $terminator;
    $bitStream = '';
    foreach (str_split($message) as $char) {
        $bitStream .= str_pad(decbin(ord($char)), 8, '0', STR_PAD_LEFT);
    }

    if (strlen($bitStream) > $pixels * 3) {
        imagedestroy($img);
        dieMessage("Message too large for image.", php_sapi_name() === 'cli');
    }

    $bitIndex = 0;
    for ($y = 0; $y < $height; $y++) {
        for ($x = 0; $x < $width; $x++) {
            if ($bitIndex >= strlen($bitStream)) break 2;

            $rgb = imagecolorat($img, $x, $y);
            $r = ($rgb >> 16) & 0xFF;
            $g = ($rgb >> 8) & 0xFF;
            $b = $rgb & 0xFF;

            $channels = ['r', 'g', 'b'];
            foreach ($channels as $channel) {
                if ($bitIndex >= strlen($bitStream)) break;
                $$channel = ($$channel & 0xFE) | ($bitStream[$bitIndex++] & 1);
            }

            $color = imagecolorallocate($img, $r, $g, $b);
            imagesetpixel($img, $x, $y, $color);
        }
    }

    if (!imagejpeg($img, $outPath, 90)) {
        imagedestroy($img);
        dieMessage("Error saving output image.", php_sapi_name() === 'cli');
    }

    imagedestroy($img);
    echo php_sapi_name() === 'cli' ? "✅ Message embedded into $outPath\n" : "<p>Message embedded into $outPath. <a href='?download=1'>Download</a></p>";
}

function extractMessage($imagePath, $terminator) {
    $img = @imagecreatefromjpeg($imagePath);
    if (!$img) dieMessage("Error loading image.", php_sapi_name() === 'cli');

    $width = imagesx($img);
    $height = imagesy($img);
    $bits = '';

    for ($y = 0; $y < $height; $y++) {
        for ($x = 0; $x < $width; $x++) {
            $rgb = imagecolorat($img, $x, $y);
            $bits .= ($rgb >> 16) & 1; // R
            $bits .= ($rgb >> 8) & 1;  // G
            $bits .= $rgb & 1;         // B
        }
    }

    $message = '';
    for ($i = 0; $i + 7 < strlen($bits); $i += 8) {
        $char = chr(bindec(substr($bits, $i, 8)));
        $message .= $char;
        if (substr($message, -strlen($terminator)) === $terminator) {
            $message = substr($message, 0, -strlen($terminator));
            break;
        }
    }

    imagedestroy($img);
    return $message;
}

function getPayload($payloadArg, $isCli) {
    if ($isCli && $payloadArg && file_exists($payloadArg)) {
        $payload = file_get_contents($payloadArg);
        if ($payload === false) {
            dieMessage("Error reading payload file.", $isCli);
        }
        return $payload;
    } elseif (!$isCli && !empty($_POST['payload'])) {
        return $_POST['payload'];
    }
    // Default lab-safe payload (simulated reverse shell)
    return <<<'EOF'
/* Simulated reverse shell for lab (disabled) */
$host = '127.0.0.1';
$port = 4444;
// $sock = fsockopen($host, $port);
// while ($cmd = fgets($sock)) {
//     $output = shell_exec($cmd);
//     fwrite($sock, $output);
// }
/* Simulated PowerShell payload (base64-encoded, not executed) */
$ps = 'Write-Output "Simulated PowerShell payload"';
$ps_b64 = base64_encode($ps);
/* Simulated Bash payload (base64-encoded, not executed) */
$bash = 'echo "Simulated Bash payload"';
$bash_b64 = base64_encode($bash);
echo "Shell payload logged for lab. PowerShell: $ps_b64, Bash: $bash_b64";
EOF;
}

function logPayload($decoded, $input, $isCli) {
    if (!is_dir(dirname(DEFAULT_LOG))) {
        mkdir(dirname(DEFAULT_LOG), 0755, true);
    }
    $logData = json_encode([
        'timestamp' => date('c'),
        'decoded' => $decoded,
        'source' => $input,
        'os' => php_uname('s') // OS detection
    ], JSON_PRETTY_PRINT);
    if ($logData === false) {
        dieMessage("Failed to encode JSON log.", $isCli);
    }
    if (!file_put_contents(DEFAULT_LOG, $logData)) {
        dieMessage("Failed to write log.", $isCli);
    }
}

// ========= EXECUTE =========
if ($mode === 'encode') {
    $msg = $isCli ? "\n[+] Encoding Mode\n" : "<p>Encoding Mode</p>";
    echo $msg;
    $payload = getPayload($payloadFile ?? null, $isCli);
    $encrypted = encryptMessage($payload, $key);
    embedMessage($input, $output, $encrypted, TERMINATOR);
} elseif ($mode === 'decode') {
    $msg = $isCli ? "\n[+] Decoding Mode\n" : "<p>Decoding Mode</p>";
    echo $msg;
    $encoded = extractMessage($input, TERMINATOR);
    $decrypted = decryptMessage($encoded, $key);
    logPayload($decrypted, $input, $isCli);
    $msg = $isCli ? "✅ Payload extracted: $decrypted\n📝 Logged to: " . DEFAULT_LOG . "\n" : "<p>Payload extracted: $decrypted<br>Logged to: " . DEFAULT_LOG . "</p>";
    echo $msg;
} else {
    dieMessage("Invalid mode: use -m encode|decode", $isCli);
}
?>
