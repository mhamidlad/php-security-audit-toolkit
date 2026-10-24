<?php
// Example secure PHP file — demonstrates proper security practices.

// Secure SQL query using prepared statements
$stmt = $db->prepare("SELECT * FROM users WHERE email = ?");
$stmt->execute([$email]);
$result = $stmt->fetchAll();

// Secure command execution with escapeshellarg
$safe_host = escapeshellarg($_POST['host']);
$output = shell_exec("ping -c 4 " . $safe_host);

// Secure output with htmlspecialchars
echo htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');

// Secure deserialization using JSON
$data = json_decode($_COOKIE['data'], true);

// Secure file inclusion with whitelist
$allowed_pages = ['home', 'about', 'contact'];
$page = $_GET['page'];
if (in_array($page, $allowed_pages, true)) {
    include(__DIR__ . "/pages/" . $page . ".php");
}

// Secure file reading with path validation
$file = basename($_GET['file']);
$safe_path = realpath(__DIR__ . "/uploads/" . $file);
if ($safe_path && strpos($safe_path, __DIR__ . "/uploads/") === 0) {
    $content = file_get_contents($safe_path);
}

// Secure password hashing
$hashed = password_hash($password, PASSWORD_BCRYPT);

// Secure random token
$token = bin2hex(random_bytes(32));

// Secure redirect with whitelist
$allowed_redirects = ['dashboard', 'profile', 'settings'];
$redirect = $_GET['redirect'];
if (in_array($redirect, $allowed_redirects, true)) {
    header("Location: /" . $redirect);
}

// Secure configuration
ini_set('display_errors', '0');
error_reporting(0);
