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

// Build email
$to = 'info@futuregatehc.com';
$subject = 'New Contact from futuregatehc.com - ' . $name;

$body = "
<html>
<body style='font-family: Arial, sans-serif; color: #333;'>
<h2 style='color: #1D4ED8;'>New Contact Form Submission</h2>
<table style='border-collapse: collapse; width: 100%; max-width: 600px;'>
    <tr style='border-bottom: 1px solid #eee;'>
        <td style='padding: 10px; font-weight: bold; width: 160px;'>Name</td>
        <td style='padding: 10px;'>{$name}</td>
    </tr>
    <tr style='border-bottom: 1px solid #eee;'>
        <td style='padding: 10px; font-weight: bold;'>Email</td>
        <td style='padding: 10px;'><a href='mailto:{$email}'>{$email}</a></td>
    </tr>
    <tr style='border-bottom: 1px solid #eee;'>
        <td style='padding: 10px; font-weight: bold;'>Phone</td>
        <td style='padding: 10px;'>{$phone}</td>
    </tr>
    <tr style='border-bottom: 1px solid #eee;'>
        <td style='padding: 10px; font-weight: bold;'>Organization</td>
        <td style='padding: 10px;'>{$organization}</td>
    </tr>
    <tr style='border-bottom: 1px solid #eee;'>
        <td style='padding: 10px; font-weight: bold;'>Solutions of Interest</td>
        <td style='padding: 10px;'>{$solutionsList}</td>
    </tr>
    <tr>
        <td style='padding: 10px; font-weight: bold; vertical-align: top;'>Message</td>
        <td style='padding: 10px;'>" . nl2br($message) . "</td>
    </tr>
</table>
<hr style='margin-top: 20px; border: none; border-top: 1px solid #eee;'>
<p style='font-size: 12px; color: #999;'>This message was sent from the contact form at futuregatehc.com</p>
</body>
</html>
";

// Use info@ as the From address (must be a real mailbox on Bluehost)
$headers  = "MIME-Version: 1.0\r\n";
$headers .= "Content-Type: text/html; charset=UTF-8\r\n";
$headers .= "From: info@futuregatehc.com\r\n";
$headers .= "Reply-To: {$email}\r\n";
$headers .= "X-Mailer: PHP/" . phpversion() . "\r\n";

// Send email with -f flag for Bluehost envelope sender
$sent = mail($to, $subject, $body, $headers, '-f info@futuregatehc.com');

// Log result for debugging
$logFile = __DIR__ . '/form-log.txt';
$logEntry = date('Y-m-d H:i:s') . " | Name: {$name} | Email: {$email} | Sent: " . ($sent ? 'YES' : 'NO') . " | Error: " . error_get_last()['message'] ?? 'none' . "\n";
file_put_contents($logFile, $logEntry, FILE_APPEND | LOCK_EX);

if ($sent) {
    header('Location: contact.html?submitted=true');
} else {
    header('Location: contact.html?error=send');
}
exit;
?>
