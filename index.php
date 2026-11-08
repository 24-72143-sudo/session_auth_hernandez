<?php
session_start();

header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');

if (isset($_SESSION['user_id'])) {
    header('Location: dashboard.php');
    exit;
}

require 'db.php';

$error = '';
$success = isset($_GET['registered']) ? 'Account created. You can log in now.' : '';
$login = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $login = trim((string)($_POST['login'] ?? ''));
    $password = (string)($_POST['password'] ?? '');

    if ($login === '' || $password === '') {
        $error = 'Enter your username and password.';
    } else {
        $stmt = $pdo->prepare('SELECT id, username, email, password_hash FROM `user` WHERE username = ? OR email = ? LIMIT 1');
        $stmt->execute([$login, $login]);
        $user = $stmt->fetch();

        if ($user && password_verify($password, $user['password_hash'])) {
            session_regenerate_id(true);

            $_SESSION['user_id'] = (int) $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['email'] = $user['email'];
            $_SESSION['login_time'] = time();
            $_SESSION['session_id'] = session_id();
            $_SESSION['fingerprint'] = hash('sha256', ($_SERVER['HTTP_USER_AGENT'] ?? '') . '|' . ($_SERVER['REMOTE_ADDR'] ?? ''));

            header('Location: dashboard.php');
            exit;
        }

        $error = 'Incorrect username or password.';
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Log in</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        :root {
            --mint-50: #f1fff8;
            --mint-100: #dffdf0;
            --mint-200: #c4f7dd;
            --mint-400: #7ad8a5;
            --mint-500: #4cc98a;
            --mint-600: #2ebd7a;
            --mint-700: #1f9d62;
            --text: #183b2d;
            --muted: #5d7a6d;
            --card: #ffffff;
            --bg: linear-gradient(135deg, #effcf5 0%, #dffaf2 100%);
        }

        body {
            background: var(--bg);
            min-height: 100vh;
            display: flex;
            align-items: center;
            color: var(--text);
            font-family: Arial, sans-serif;
        }

        .auth-card {
            max-width: 400px;
            width: 100%;
            margin: auto;
            border: 0;
            border-radius: 16px;
            background: var(--card);
            box-shadow: 0 12px 32px rgba(29, 117, 78, 0.15);
        }

        .btn-primary {
            background: linear-gradient(135deg, var(--mint-500), var(--mint-600));
            border-color: var(--mint-600);
        }

        .btn-primary:hover,
        .btn-primary:focus,
        .btn-primary:active {
            background: linear-gradient(135deg, var(--mint-600), var(--mint-700));
            border-color: var(--mint-700);
        }

        .form-control:focus {
            border-color: var(--mint-500);
            box-shadow: 0 0 0 0.2rem rgba(76, 201, 138, 0.18);
        }

        a {
            color: var(--mint-700);
            text-decoration: none;
        }

        a:hover {
            color: var(--mint-600);
        }

        .alert-success {
            background: var(--mint-100);
            border-color: var(--mint-200);
            color: var(--text);
        }

        .user-icon-wrap {
            width: 72px;
            height: 72px;
            margin: 0 auto 1rem auto;
            border-radius: 50%;
            background: linear-gradient(135deg, var(--mint-500), var(--mint-700));
            display: flex;
            align-items: center;
            justify-content: center;
            box-shadow: 0 10px 20px rgba(46, 189, 122, 0.25);
        }

        .user-icon {
            width: 34px;
            height: 34px;
            display: block;
        }
    </style>
</head>
<body>
<div class="card auth-card p-4">
    <div class="user-icon-wrap" aria-label="User icon">
        <svg class="user-icon" viewBox="0 0 24 24" aria-hidden="true">
            <circle cx="12" cy="7.2" r="3.7" fill="white"></circle>
            <path d="M4 19.2c1.8-3.1 4.6-4.7 8-4.7s6.2 1.6 8 4.7" fill="none" stroke="white" stroke-width="2.3" stroke-linecap="round"></path>
        </svg>
    </div>
    <h1 class="h4 mb-1 text-center">Welcome back</h1>
    <p class="text-muted mb-4 text-center">Sign in to your account</p>

    <?php if ($success): ?>
        <div class="alert alert-success py-2"><?= htmlspecialchars($success) ?></div>
    <?php endif; ?>
    <?php if ($error): ?>
        <div class="alert alert-danger py-2"><?= htmlspecialchars($error) ?></div>
    <?php endif; ?>

    <form method="post" autocomplete="off">
        <div class="mb-3">
            <label for="login" class="form-label">Username or email</label>
            <input type="text" class="form-control" id="login" name="login" value="<?= htmlspecialchars($login) ?>" required>
        </div>
        <div class="mb-3">
            <label for="password" class="form-label">Password</label>
            <input type="password" class="form-control" id="password" name="password" required>
        </div>
        <button type="submit" class="btn btn-primary w-100">Log in</button>
    </form>

    <p class="text-center mt-3 mb-0">No account? <a href="register.php">Register</a></p>
</div>

<script>
    window.addEventListener('pageshow', function (e) {
        if (e.persisted) { window.location.reload(); }
    });
</script>
</body>
</html>
