# Remediation Guide

## SQL Injection (PHP001)

**Vulnerable:**
```php
$query = "SELECT * FROM users WHERE email = '" . $email . "'";
$result = $db->query($query);
```

**Secure:**
```php
$stmt = $db->prepare("SELECT * FROM users WHERE email = ?");
$stmt->execute([$email]);
$result = $stmt->fetchAll();
```

Parameterized queries separate SQL structure from data, preventing user input
from being interpreted as SQL commands.

## Command Injection (PHP002)

**Vulnerable:**
```php
$output = shell_exec("ping " . $user_input);
```

**Secure:**
```php
$output = shell_exec("ping " . escapeshellarg($user_input));
```

`escapeshellarg()` escapes single quotes and wraps the argument in single
quotes, preventing shell metacharacter injection. Consider avoiding shell
execution entirely by using PHP's built-in functions.

## Cross-Site Scripting (PHP003)

**Vulnerable:**
```php
echo $_GET["name"];
```

**Secure:**
```php
echo htmlspecialchars($_GET["name"], ENT_QUOTES, "UTF-8");
```

Use `htmlspecialchars()` for HTML context. For JavaScript, CSS, or URL
contexts, use context-specific encoding or a template engine with auto-escaping.

## Unsafe Deserialization (PHP004)

**Vulnerable:**
```php
$data = unserialize($user_input);
```

**Secure:**
```php
$data = json_decode($user_input, true);
```

`json_decode()` does not allow code execution. If `unserialize()` is
unavoidable, use the `allowed_classes` option to restrict deserialized types.

## Weak Password Hashing (PHP009)

**Vulnerable:**
```php
$hashed = md5($password);
```

**Secure:**
```php
$hashed = password_hash($password, PASSWORD_BCRYPT);
// Verification:
if (password_verify($input, $hashed)) { ... }
```

`password_hash()` uses bcrypt (or Argon2) with automatic salt generation and
adjustable cost factor.

## Insecure Randomness (PHP008)

**Vulnerable:**
```php
$token = mt_rand();
```

**Secure:**
```php
$token = bin2hex(random_bytes(32));
```

`random_bytes()` uses a cryptographically secure random number generator.

## Hardcoded Secrets (SEC001-SEC004)

**Remediation steps:**
1. Revoke or rotate the exposed credential immediately.
2. Remove it from source code and git history.
3. Store the replacement in an environment variable or secret manager.
4. Add automated secret detection to prevent future leaks.
5. Review where the credential was used.

**Never** remove a secret from only the latest commit if it was committed to
git history. Assume it has been copied and rotate it.
