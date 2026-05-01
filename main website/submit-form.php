<?php
// Only allow POST requests
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: contact.html');
    exit;
}

// Sanitize input
function clean($str) {
    return htmlspecialchars(trim($str), ENT_QUOTES, 'UTF-8');
}

$name = clean($_POST['name'] ?? '');
$email = filter_var(trim($_POST['email'] ?? ''), FILTER_SANITIZE_EMAIL);
$phone = clean($_POST['phone'] ?? '');
$organization = clean($_POST['organization'] ?? '');
$message = clean($_POST['message'] ?? '');

// Solutions (array of checkboxes)
$solutions = [];
if (!empty($_POST['solutions']) && is_array($_POST['solutions'])) {
    foreach ($_POST['solutions'] as $sol) {
        $solutions[] = clean($sol);
    }
}
$solutionsList = !empty($solutions) ? implode(', ', $solutions) : 'None selected';

// Honeypot spam check
if (!empty($_POST['website'])) {
    header('Location: contact.html?submitted=true');
    exit;
}

// Validate required fields
if (empty($name) || empty($email) || empty($message) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
    header('Location: contact.html?error=missing');
    exit;
}

// SMTP Configuration
$smtpHost = 'smtp.office365.com';
$smtpPort = 587;
$smtpUser = 'info@futuregatehc.com';
$smtpPass = 'Future@1278';
$to = 'info@futuregatehc.com';
$subject = 'New Contact from futuregatehc.com - ' . $name;

$body = "<html><body style='font-family:Arial,sans-serif;color:#333;'>"
    . "<h2 style='color:#1D4ED8;'>New Contact Form Submission</h2>"
    . "<table style='border-collapse:collapse;width:100%;max-width:600px;'>"
    . "<tr style='border-bottom:1px solid #eee;'><td style='padding:10px;font-weight:bold;width:160px;'>Name</td><td style='padding:10px;'>{$name}</td></tr>"
    . "<tr style='border-bottom:1px solid #eee;'><td style='padding:10px;font-weight:bold;'>Email</td><td style='padding:10px;'><a href='mailto:{$email}'>{$email}</a></td></tr>"
    . "<tr style='border-bottom:1px solid #eee;'><td style='padding:10px;font-weight:bold;'>Phone</td><td style='padding:10px;'>{$phone}</td></tr>"
    . "<tr style='border-bottom:1px solid #eee;'><td style='padding:10px;font-weight:bold;'>Organization</td><td style='padding:10px;'>{$organization}</td></tr>"
    . "<tr style='border-bottom:1px solid #eee;'><td style='padding:10px;font-weight:bold;'>Solutions of Interest</td><td style='padding:10px;'>{$solutionsList}</td></tr>"
    . "<tr><td style='padding:10px;font-weight:bold;vertical-align:top;'>Message</td><td style='padding:10px;'>" . nl2br($message) . "</td></tr>"
    . "</table>"
    . "<hr style='margin-top:20px;border:none;border-top:1px solid #eee;'>"
    . "<p style='font-size:12px;color:#999;'>This message was sent from the contact form at futuregatehc.com</p>"
    . "</body></html>";

// Send via SMTP
function smtpSend($host, $port, $user, $pass, $to, $subject, $htmlBody, $replyTo, $replyName) {
    $error = '';

    $sock = @stream_socket_client("tcp://{$host}:{$port}", $errno, $errstr, 30);
    if (!$sock) return "Connection failed: {$errstr}";

    $resp = fgets($sock, 512);
    if (substr($resp, 0, 3) !== '220') return "Bad greeting: {$resp}";

    // EHLO
    fwrite($sock, "EHLO futuregatehc.com\r\n");
    while ($line = fgets($sock, 512)) { if ($line[3] === ' ') break; }

    // STARTTLS
    fwrite($sock, "STARTTLS\r\n");
    $resp = fgets($sock, 512);
    if (substr($resp, 0, 3) !== '220') return "STARTTLS failed: {$resp}";

    $crypto = stream_socket_enable_crypto($sock, true, STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT);
    if (!$crypto) return "TLS negotiation failed";

    // EHLO again after TLS
    fwrite($sock, "EHLO futuregatehc.com\r\n");
    while ($line = fgets($sock, 512)) { if ($line[3] === ' ') break; }

    // AUTH LOGIN
    fwrite($sock, "AUTH LOGIN\r\n");
    $resp = fgets($sock, 512);
    if (substr($resp, 0, 3) !== '334') return "AUTH not accepted: {$resp}";

    fwrite($sock, base64_encode($user) . "\r\n");
    $resp = fgets($sock, 512);
    if (substr($resp, 0, 3) !== '334') return "Username rejected: {$resp}";

    fwrite($sock, base64_encode($pass) . "\r\n");
    $resp = fgets($sock, 512);
    if (substr($resp, 0, 3) !== '235') return "Auth failed: {$resp}";

    // MAIL FROM
    fwrite($sock, "MAIL FROM:<{$user}>\r\n");
    $resp = fgets($sock, 512);
    if (substr($resp, 0, 3) !== '250') return "MAIL FROM rejected: {$resp}";

    // RCPT TO
    fwrite($sock, "RCPT TO:<{$to}>\r\n");
    $resp = fgets($sock, 512);
    if (substr($resp, 0, 3) !== '250') return "RCPT TO rejected: {$resp}";

    // DATA
    fwrite($sock, "DATA\r\n");
    $resp = fgets($sock, 512);
    if (substr($resp, 0, 3) !== '354') return "DATA rejected: {$resp}";

    // Build message
    $boundary = md5(time());
    $msg  = "From: FutureGate Healthcare <{$user}>\r\n";
    $msg .= "To: <{$to}>\r\n";
    $msg .= "Reply-To: {$replyName} <{$replyTo}>\r\n";
    $msg .= "Subject: {$subject}\r\n";
    $msg .= "MIME-Version: 1.0\r\n";
    $msg .= "Content-Type: text/html; charset=UTF-8\r\n";
    $msg .= "Date: " . date('r') . "\r\n";
    $msg .= "\r\n";
    $msg .= $htmlBody . "\r\n";
    $msg .= ".\r\n";

    fwrite($sock, $msg);
    $resp = fgets($sock, 512);
    if (substr($resp, 0, 3) !== '250') return "Message rejected: {$resp}";

    // QUIT
    fwrite($sock, "QUIT\r\n");
    fclose($sock);

    return ''; // empty = success
}

$result = smtpSend($smtpHost, $smtpPort, $smtpUser, $smtpPass, $to, $subject, $body, $email, $name);

// Log result
$logFile = __DIR__ . '/form-log.txt';
$status = empty($result) ? 'SUCCESS' : "FAILED: {$result}";
$logEntry = date('Y-m-d H:i:s') . " | Name: {$name} | Email: {$email} | Status: {$status}\n";
file_put_contents($logFile, $logEntry, FILE_APPEND | LOCK_EX);

if (empty($result)) {
    header('Location: contact.html?submitted=true');
} else {
    header('Location: contact.html?error=send');
}
exit;
?>
