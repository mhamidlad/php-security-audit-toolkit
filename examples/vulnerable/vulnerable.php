<?php
// Example vulnerable PHP file — for testing and demonstration only.
// DO NOT use this code in production.

// PHP001: SQL Injection
$email = $_GET['email'];
$query = "SELECT * FROM users WHERE email = '" . $email . "'";
$result = $db->query($query);

// PHP002: Command Injection
$user_input = $_POST['host'];
$output = shell_exec("ping -c 4 " . $user_input);

// PHP003: Cross-Site Scripting
echo $_GET['name'];

// PHP004: Unsafe Deserialization
$data = unserialize($_COOKIE['data']);

// PHP005: File Inclusion
$page = $_GET['page'];
include($page . ".php");

// PHP006: Path Traversal
$file = $_GET['file'];
$content = file_get_contents($file);

// PHP007: Weak Cryptography
$hash = md5($password);

// PHP008: Insecure Randomness
$token = mt_rand();

// PHP009: Weak Password Hashing
$hashed = md5($password);

// PHP010: Unsafe Redirect
header("Location: " . $_GET['url']);

// PHP012: Debug Exposure
ini_set('display_errors', '1');
error_reporting(E_ALL);

// SEC001: Hardcoded API Key
$api_key = "sk-1234567890abcdefghijklmnop";

// SEC002: Private Key
$private_key = "-----BEGIN RSA PRIVATE KEY-----MIIEowIBAAKCAQEA...-----END RSA PRIVATE KEY-----";

// SEC003: Database Credential
$db_password = "my_secret_db_pass_123";
