<?php
declare(strict_types=1);
/*
 * BETTING WORLD — DEMO ONLY
 * PHP 8.1+ / MySQL 8+
 * Configure DB + SMTP below. Real-money wagering, deposits and withdrawals are
 * intentionally unavailable. Credits are non-transferable and have no cash value.
 */
session_name('bw_customer');
ini_set('session.use_strict_mode', '1');
ini_set('session.cookie_httponly', '1');
ini_set('session.cookie_samesite', 'Lax');
if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ini_set('session.cookie_secure', '1');
session_start();

const BW_DEMO_ONLY = true;
const DB_HOST = 'localhost';
const DB_NAME = 'betting_world';
const DB_USER = 'YOUR_DB_USERNAME';
const DB_PASS = 'YOUR_DB_PASSWORD';

/* SMTP configuration — keep credentials server-side. */
const SMTP_HOST = 'smtp.example.com';
const SMTP_PORT = 587; // 587 STARTTLS, 465 implicit TLS
const SMTP_USER = 'your-smtp-username';
const SMTP_PASS = 'your-smtp-password';
const SMTP_FROM = 'no-reply@example.com';
const SMTP_FROM_NAME = 'BETTING WORLD';

function db(): PDO {
    static $pdo = null;
    if ($pdo instanceof PDO) return $pdo;
    $pdo = new PDO('mysql:host='.DB_HOST.';dbname='.DB_NAME.';charset=utf8mb4', DB_USER, DB_PASS, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false
    ]);
    return $pdo;
}
function e($v): string { return htmlspecialchars((string)$v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
function json_out(array $data, int $status=200): never {
    http_response_code($status); header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data, JSON_UNESCAPED_SLASHES); exit;
}
function csrf(): string { if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(32)); return $_SESSION['csrf']; }
function check_csrf(): void {
    $token = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? ($_POST['csrf'] ?? '');
    if (!$token || !hash_equals(csrf(), $token)) json_out(['ok'=>false,'message'=>'Security token expired. Refresh and try again.'], 419);
}
function user(): ?array {
    if (empty($_SESSION['uid'])) return null;
    $q = db()->prepare("SELECT id,full_name,username,email,mobile,dob,status,email_verified,created_at FROM users WHERE id=?");
    $q->execute([$_SESSION['uid']]); $u=$q->fetch();
    if (!$u || $u['status'] !== 'active' || empty($u['email_verified'])) { unset($_SESSION['uid']); return null; }
    return $u;
}
function require_user(): array { $u=user(); if (!$u) json_out(['ok'=>false,'message'=>'Please sign in first.'],401); return $u; }
function send_smtp(string $to, string $subject, string $body): bool {
    if (SMTP_HOST==='smtp.example.com' || SMTP_USER==='your-smtp-username' || SMTP_FROM==='no-reply@example.com') return false;
    $remote = (SMTP_PORT===465 ? 'ssl://' : '').SMTP_HOST.':'.SMTP_PORT;
    $fp = @stream_socket_client($remote, $errno, $errstr, 12, STREAM_CLIENT_CONNECT);
    if (!$fp) return false;
    stream_set_timeout($fp, 12);
    $read = function() use ($fp) { $line=''; do { $line .= (string)fgets($fp, 515); } while (isset($line[3]) && $line[3]==='-'); return $line; };
    $cmd = function(string $s, array $codes) use ($fp,$read) {
        fwrite($fp,$s."\r\n"); $r=$read(); $code=(int)substr($r,0,3);
        return in_array($code,$codes,true);
    };
    $ok = str_starts_with($read(),'220') && $cmd('EHLO betting-world.local',[250]);
    if ($ok && SMTP_PORT!==465) {
        $ok=$cmd('STARTTLS',[220]) && stream_socket_enable_crypto($fp,true,STREAM_CRYPTO_METHOD_TLS_CLIENT);
        if ($ok) $ok=$cmd('EHLO betting-world.local',[250]);
    }
    if ($ok) $ok=$cmd('AUTH LOGIN',[334]) && $cmd(base64_encode(SMTP_USER),[334]) && $cmd(base64_encode(SMTP_PASS),[235]);
    if ($ok) $ok=$cmd('MAIL FROM:<'.SMTP_FROM.'>',[250]) && $cmd('RCPT TO:<'.$to.'>',[250,251]) && $cmd('DATA',[354]);
    if ($ok) {
        $headers="From: ".SMTP_FROM_NAME." <".SMTP_FROM.">\r\nTo: <$to>\r\nSubject: ".mb_encode_mimeheader($subject)."\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n";
        $message=$headers."\r\n".$body."\r\n.";
        $ok=$cmd($message,[250]);
    }
    $cmd('QUIT',[221]); fclose($fp); return $ok;
}
function issue_otp(string $email, string $purpose, ?int $uid): bool {
    $pdo=db();
    $q=$pdo->prepare("SELECT COUNT(*) FROM otp_verifications WHERE email=? AND purpose=? AND created_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR)");
    $q->execute([$email,$purpose]); if ((int)$q->fetchColumn()>=3) return false;
    $q=$pdo->prepare("SELECT created_at FROM otp_verifications WHERE email=? AND purpose=? ORDER BY id DESC LIMIT 1");
    $q->execute([$email,$purpose]); $last=$q->fetchColumn();
    if ($last && strtotime((string)$last)>time()-60) return false;
    $otp=(string)random_int(100000,999999); $hash=password_hash($otp,PASSWORD_DEFAULT);
    $pdo->prepare("UPDATE otp_verifications SET expires_at=NOW(), verified_at=NOW() WHERE email=? AND purpose=? AND verified_at IS NULL")->execute([$email,$purpose]);
    $pdo->prepare("INSERT INTO otp_verifications(user_id,email,otp_hash,purpose,expires_at,attempts,created_at) VALUES(?,?,?,?,DATE_ADD(NOW(),INTERVAL 5 MINUTE),0,NOW())")
        ->execute([$uid,$email,$hash,$purpose]);
    $sent=send_smtp($email,'Your BETTING WORLD verification code',"Your verification code is: $otp\nIt expires in 5 minutes. If you did not request this, ignore this email.");
    $pdo->prepare("INSERT INTO otp_delivery_logs(user_id,destination,delivery_method,delivery_status,created_at) VALUES(?,?, 'email', ?, NOW())")
        ->execute([$uid,$email,$sent?'sent':'failed']);
    return $sent;
}
function verify_otp(string $email,string $purpose,string $otp): ?array {
    $pdo=db(); $q=$pdo->prepare("SELECT * FROM otp_verifications WHERE email=? AND purpose=? AND verified_at IS NULL AND expires_at>NOW() ORDER BY id DESC LIMIT 1");
    $q->execute([$email,$purpose]); $row=$q->fetch();
    if (!$row || (int)$row['attempts']>=5) return null;
    if (!password_verify($otp,$row['otp_hash'])) {
        $pdo->prepare("UPDATE otp_verifications SET attempts=attempts+1 WHERE id=?")->execute([$row['id']]); return null;
    }
    $pdo->prepare("UPDATE otp_verifications SET verified_at=NOW() WHERE id=?")->execute([$row['id']]); return $row;
}
function wallet_balance(int $uid): string {
    $q=db()->prepare("SELECT balance FROM wallets WHERE user_id=?"); $q->execute([$uid]); return (string)($q->fetchColumn() ?: '0.00');
}
function add_demo_credits(int $uid, float $amount, string $kind, string $note): void {
    if ($amount<=0 || $amount>10000) throw new RuntimeException('Invalid demo-credit amount.');
    $pdo=db(); $pdo->beginTransaction();
    try {
        $q=$pdo->prepare("SELECT balance FROM wallets WHERE user_id=? FOR UPDATE"); $q->execute([$uid]); $bal=(float)$q->fetchColumn();
        if ($bal+$amount<0) throw new RuntimeException('Insufficient demo credits.');
        $pdo->prepare("UPDATE wallets SET balance=balance+?,updated_at=NOW() WHERE user_id=?")->execute([$amount,$uid]);
        $pdo->prepare("INSERT INTO transactions(user_id,type,amount,status,reference,note,created_at) VALUES(?,?,?,'completed',?,?,NOW())")
            ->execute([$uid,$kind,$amount,'DEMO-'.bin2hex(random_bytes(6)),$note]);
        $pdo->commit();
    } catch(Throwable $t) { $pdo->rollBack(); throw $t; }
}
function play_game(array $u,int $gameId,array $input): array {
    $pdo=db(); $q=$pdo->prepare("SELECT * FROM games WHERE id=? AND is_enabled=1"); $q->execute([$gameId]); $game=$q->fetch();
    if (!$game) throw new RuntimeException('Game is unavailable.');
    $allowed=[1=>'Crash Flight',2=>'Colour Prediction',3=>'Number Prediction',4=>'Dice Duel',5=>'Spin Wheel',6=>'Coin Flip',7=>'Mines',8=>'Plinko',9=>'Bingo',10=>'Roulette',11=>'Hi-Lo',12=>'Cricket Prediction',13=>'Memory Match',14=>'Lucky Number',15=>'Fantasy Sports Prediction'];
    if (!isset($allowed[$gameId])) throw new RuntimeException('Unknown game.');
    $choice=substr(trim((string)($input['choice']??'')),0,40);
    $result=''; $detail=[];
    switch($gameId) {
        case 1: $m=random_int(100,500)/100; $result='Crash point: '.number_format($m,2).'x'; $detail=['multiplier'=>$m]; break;
        case 2: $result=['Red','Green','Violet'][random_int(0,2)]; break;
        case 3: $result=(string)random_int(0,9); break;
        case 4: $result=(string)random_int(1,6).' + '.random_int(1,6); break;
        case 5: $result=['Star','Crown','Diamond','Bonus','Moon'][random_int(0,4)]; break;
        case 6: $result=random_int(0,1)?'Heads':'Tails'; break;
        case 7: $result='Safe tiles: '.random_int(1,8).' / 9'; break;
        case 8: $result='Landing slot '.random_int(1,9); break;
        case 9: $result='Bingo number '.random_int(1,75); break;
        case 10: $n=random_int(0,36); $result='Number '.$n.' — '.($n===0?'Green':($n%2?'Red':'Black')); break;
        case 11: $result='Card value '.random_int(1,13); break;
        case 12: $result='Demo score: '.random_int(80,240).'/6'; break;
        case 13: $result='Demo memory round completed'; break;
        case 14: $result='Lucky number '.random_int(0,99); break;
        case 15: $result='Demo fantasy points: '.random_int(20,160); break;
    }
    $pdo->prepare("INSERT INTO game_sessions(user_id,game_id,choice,result,status,created_at) VALUES(?,?,?,?,'completed',NOW())")
        ->execute([$u['id'],$gameId,$choice,$result]);
    $sessionId=(int)$pdo->lastInsertId();
    $pdo->prepare("INSERT INTO game_results(session_id,user_id,game_id,result_data,created_at) VALUES(?,?,?,?,NOW())")
        ->execute([$sessionId,$u['id'],$gameId,json_encode(['result'=>$result,'details'=>$detail])]);
    return ['session_id'=>$sessionId,'result'=>$result,'detail'=>$detail];
}

/* API actions */
if (isset($_GET['api'])) {
    try {
        if ($_SERVER['REQUEST_METHOD']==='POST') check_csrf();
        $action=(string)($_GET['api']??'');
        if ($action==='register') {
            $name=trim($_POST['full_name']??''); $username=trim($_POST['username']??''); $email=strtolower(trim($_POST['email']??''));
            $mobile=preg_replace('/\D+/','',$_POST['mobile']??''); $dob=$_POST['dob']??''; $pass=$_POST['password']??'';
            if (strlen($name)<2 || !preg_match('/^[a-zA-Z0-9_]{3,24}$/',$username) || !filter_var($email,FILTER_VALIDATE_EMAIL) ||
                !preg_match('/^[6-9]\d{9}$/',$mobile) || !$dob || strlen($pass)<10 || !preg_match('/[A-Z]/',$pass) || !preg_match('/[a-z]/',$pass) || !preg_match('/\d/',$pass) || $pass!==($_POST['confirm_password']??'')) json_out(['ok'=>false,'message'=>'Check all fields. Password needs 10+ characters with upper/lowercase and a number.'],422);
            $age=(new DateTime($dob))->diff(new DateTime('today'))->y;
            if ($age<18 || $dob>=date('Y-m-d')) json_out(['ok'=>false,'message'=>'You must be at least 18 years old.'],422);
            $q=db()->prepare("SELECT id FROM users WHERE username=? OR email=? LIMIT 1"); $q->execute([$username,$email]);
            if ($q->fetch()) json_out(['ok'=>false,'message'=>'Username or email already registered.'],409);
            $pdo=db(); $pdo->beginTransaction();
            $pdo->prepare("INSERT INTO users(full_name,username,email,mobile,dob,password_hash,status,email_verified,created_at) VALUES(?,?,?,?,?,?,'pending',0,NOW())")
                ->execute([$name,$username,$email,$mobile,$dob,password_hash($pass,PASSWORD_DEFAULT)]);
            $uid=(int)$pdo->lastInsertId();
            $pdo->prepare("INSERT INTO wallets(user_id,balance,pending_balance,updated_at) VALUES(?,1000.00,0,NOW())")->execute([$uid]);
            $pdo->commit();
            if (!issue_otp($email,'register',$uid)) json_out(['ok'=>false,'message'=>'Account created, but email could not be sent or OTP rate limit reached. Contact support; no OTP was delivered.'],503);
            json_out(['ok'=>true,'message'=>'Verification email sent. Enter the 6-digit code.','email'=>$email]);
        }
        if ($action==='verify_register') {
            $email=strtolower(trim($_POST['email']??'')); $row=verify_otp($email,'register',trim($_POST['otp']??''));
            if (!$row) json_out(['ok'=>false,'message'=>'Invalid or expired OTP.'],422);
            db()->prepare("UPDATE users SET status='active',email_verified=1 WHERE id=?")->execute([$row['user_id']]);
            json_out(['ok'=>true,'message'=>'Email verified. You can now sign in.']);
        }
        if ($action==='login') {
            $who=trim($_POST['identity']??''); $pass=$_POST['password']??'';
            $q=db()->prepare("SELECT * FROM users WHERE username=? OR email=? LIMIT 1"); $q->execute([$who,strtolower($who)]); $u=$q->fetch();
            if (!$u || !password_verify($pass,$u['password_hash']) || $u['status']!=='active' || !$u['email_verified']) json_out(['ok'=>false,'message'=>'Invalid credentials or account not verified.'],401);
            if (!issue_otp($u['email'],'login',(int)$u['id'])) json_out(['ok'=>false,'message'=>'OTP email failed or rate limit reached.'],503);
            $_SESSION['pending_login']=(int)$u['id']; json_out(['ok'=>true,'message'=>'Login OTP sent to your email.','email'=>$u['email']]);
        }
        if ($action==='otp_login_request') {
            $email=strtolower(trim($_POST['email']??'')); $q=db()->prepare("SELECT id FROM users WHERE email=? AND status='active' AND email_verified=1"); $q->execute([$email]); $uid=$q->fetchColumn();
            if (!$uid || !issue_otp($email,'otp_login',(int)$uid)) json_out(['ok'=>false,'message'=>'Unable to send OTP. Check email or try later.'],400);
            $_SESSION['pending_login']=(int)$uid; json_out(['ok'=>true,'message'=>'Login OTP sent.','email'=>$email]);
        }
        if ($action==='verify_login') {
            $uid=(int)($_SESSION['pending_login']??0); $q=db()->prepare("SELECT email FROM users WHERE id=?"); $q->execute([$uid]); $email=$q->fetchColumn();
            $purpose=($_POST['purpose']??'login')==='otp_login'?'otp_login':'login';
            $row=$email?verify_otp($email,$purpose,trim($_POST['otp']??'')):null;
            if (!$row || (int)$row['user_id']!==$uid) json_out(['ok'=>false,'message'=>'Invalid or expired OTP.'],422);
            session_regenerate_id(true); $_SESSION['uid']=$uid; unset($_SESSION['pending_login']);
            db()->prepare("INSERT INTO authentication_logs(user_id,login_method,ip_address,status,created_at) VALUES(?,?,?,'success',NOW())")->execute([$uid,$purpose,substr($_SERVER['REMOTE_ADDR']??'',0,45)]);
            json_out(['ok'=>true,'message'=>'Welcome back.']);
        }
        if ($action==='forgot_request') {
            $email=strtolower(trim($_POST['email']??'')); $q=db()->prepare("SELECT id FROM users WHERE email=? AND status='active'"); $q->execute([$email]); $uid=$q->fetchColumn();
            if (!$uid || !issue_otp($email,'reset',(int)$uid)) json_out(['ok'=>false,'message'=>'Unable to send reset OTP.'],400);
            $_SESSION['reset_email']=$email; json_out(['ok'=>true,'message'=>'Password reset OTP sent.']);
        }
        if ($action==='forgot_reset') {
            $email=(string)($_SESSION['reset_email']??''); $row=verify_otp($email,'reset',trim($_POST['otp']??''));
            $pass=$_POST['password']??'';
            if (!$row || strlen($pass)<10 || !preg_match('/[A-Z]/',$pass) || !preg_match('/[a-z]/',$pass) || !preg_match('/\d/',$pass) || $pass!==($_POST['confirm_password']??'')) json_out(['ok'=>false,'message'=>'Invalid OTP or password requirements not met.'],422);
            db()->prepare("UPDATE users SET password_hash=? WHERE id=?")->execute([password_hash($pass,PASSWORD_DEFAULT),$row['user_id']]);
            unset($_SESSION['reset_email']); json_out(['ok'=>true,'message'=>'Password updated. Sign in with your new password.']);
        }
        if ($action==='logout') { $_SESSION=[]; session_regenerate_id(true); json_out(['ok'=>true]); }
        $u=require_user();
        if ($action==='dashboard') {
            $q=db()->prepare("SELECT COUNT(*) total, SUM(status='completed') completed FROM game_sessions WHERE user_id=?"); $q->execute([$u['id']]); $stats=$q->fetch();
            $q=db()->prepare("SELECT type,amount,status,note,created_at FROM transactions WHERE user_id=? ORDER BY id DESC LIMIT 8"); $q->execute([$u['id']]);
            $q2=db()->prepare("SELECT gs.result,gs.created_at,g.name game FROM game_sessions gs JOIN games g ON g.id=gs.game_id WHERE gs.user_id=? ORDER BY gs.id DESC LIMIT 8"); $q2->execute([$u['id']]);
            json_out(['ok'=>true,'user'=>$u,'balance'=>wallet_balance((int)$u['id']),'stats'=>$stats,'transactions'=>$q->fetchAll(),'history'=>$q2->fetchAll()]);
        }
        if ($action==='games') { $q=db()->query("SELECT id,name,category,description,icon FROM games WHERE is_enabled=1 ORDER BY id"); json_out(['ok'=>true,'games'=>$q->fetchAll()]); }
        if ($action==='play') {
            $gid=(int)($_POST['game_id']??0); $result=play_game($u,$gid,$_POST);
            json_out(['ok'=>true,'message'=>'Demo round completed. No money was wagered.','result'=>$result]);
        }
        if ($action==='demo_reset') {
            $q=db()->prepare("SELECT COUNT(*) FROM transactions WHERE user_id=? AND type='demo_grant' AND created_at>DATE_SUB(NOW(),INTERVAL 1 DAY)"); $q->execute([$u['id']]);
            if ((int)$q->fetchColumn()>=3) json_out(['ok'=>false,'message'=>'Daily demo-credit limit reached.'],429);
            add_demo_credits((int)$u['id'],250,'demo_grant','Daily demo credit refresh'); json_out(['ok'=>true,'message'=>'250 demo credits added.']);
        }
        if ($action==='profile') {
            $name=trim($_POST['full_name']??''); $mobile=preg_replace('/\D+/','',$_POST['mobile']??'');
            if (strlen($name)<2 || !preg_match('/^[6-9]\d{9}$/',$mobile)) json_out(['ok'=>false,'message'=>'Enter a valid name and 10-digit mobile.'],422);
            db()->prepare("UPDATE users SET full_name=?,mobile=? WHERE id=?")->execute([$name,$mobile,$u['id']]); json_out(['ok'=>true,'message'=>'Profile updated.']);
        }
        if ($action==='change_password') {
            $q=db()->prepare("SELECT password_hash FROM users WHERE id=?"); $q->execute([$u['id']]); $hash=$q->fetchColumn();
            $new=$_POST['new_password']??'';
            if (!password_verify($_POST['current_password']??'',$hash) || strlen($new)<10 || !preg_match('/[A-Z]/',$new) || !preg_match('/[a-z]/',$new) || !preg_match('/\d/',$new)) json_out(['ok'=>false,'message'=>'Current password or new password is invalid.'],422);
            db()->prepare("UPDATE users SET password_hash=? WHERE id=?")->execute([password_hash($new,PASSWORD_DEFAULT),$u['id']]); json_out(['ok'=>true,'message'=>'Password changed.']);
        }
        if ($action==='support') {
            $subject=trim($_POST['subject']??''); $message=trim($_POST['message']??'');
            if (strlen($subject)<4 || strlen($message)<10) json_out(['ok'=>false,'message'=>'Enter a subject and a longer message.'],422);
            db()->prepare("INSERT INTO support_tickets(user_id,subject,status,created_at,updated_at) VALUES(?,?,'open',NOW(),NOW())")->execute([$u['id'],$subject]);
            $tid=(int)db()->lastInsertId(); db()->prepare("INSERT INTO support_replies(ticket_id,sender_type,sender_id,message,created_at) VALUES(?,'user',?,?,NOW())")->execute([$tid,$u['id'],$message]);
            json_out(['ok'=>true,'message'=>'Support ticket submitted.']);
        }
        if ($action==='sports') {
            $q=db()->query("SELECT m.id,m.home_team,m.away_team,m.match_date,m.status,m.demo_result,s.name sport FROM matches m JOIN sports s ON s.id=m.sport_id ORDER BY m.match_date DESC LIMIT 30");
            json_out(['ok'=>true,'matches'=>$q->fetchAll()]);
        }
        json_out(['ok'=>false,'message'=>'Unknown action.'],404);
    } catch(Throwable $t) {
        error_log('BETTING WORLD: '.$t->getMessage());
        json_out(['ok'=>false,'message'=>'A server error occurred. Check database/hosting configuration.'],500);
    }
}

$logged=user();
$csrfToken=csrf();
?><!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>BETTING WORLD — Enter the World of Gaming</title>
<style>
:root{--bg:#080d18;--panel:#111b2c;--card:#172338;--mint:#00d9a5;--gold:#f5b942;--white:#fff;--muted:#a7b1c2;--red:#ff4757}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 80% -10%,#18344a 0,transparent 35%),var(--bg);color:var(--white);font:15px/1.5 Inter,system-ui,Arial}button,input,textarea{font:inherit}button{cursor:pointer;border:0;border-radius:12px;padding:11px 17px;background:var(--mint);color:#06140f;font-weight:800}button.secondary{background:#26364d;color:#fff}button.gold{background:var(--gold)}button:disabled{opacity:.45;cursor:not-allowed}input,textarea{width:100%;background:#0c1524;border:1px solid #30415a;border-radius:10px;padding:12px;color:#fff;outline:none}input:focus,textarea:focus{border-color:var(--mint)}label{display:block;color:var(--muted);font-size:13px;margin:10px 0 5px}.top{position:sticky;top:0;z-index:4;background:#080d18eF;border-bottom:1px solid #24344a;backdrop-filter:blur(15px)}.nav{max-width:1200px;margin:auto;padding:14px 20px;display:flex;align-items:center;justify-content:space-between;gap:15px}.brand{font-size:21px;font-weight:950;letter-spacing:1px}.brand b{color:var(--mint)}.navlinks{display:flex;gap:8px;flex-wrap:wrap}.navlinks button{background:transparent;color:var(--muted);padding:8px 10px}.wrap{max-width:1200px;margin:28px auto;padding:0 20px}.hero{padding:36px;border:1px solid #28445a;border-radius:25px;background:linear-gradient(115deg,#102b3b,#172338 60%,#332a1b);display:flex;align-items:center;justify-content:space-between;gap:20px}.hero h1{font-size:clamp(30px,5vw,54px);line-height:1.05;margin:0 0 12px}.hero h1 span{color:var(--mint)}.muted{color:var(--muted)}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:15px;margin:18px 0}.card{background:linear-gradient(145deg,#192941,#111b2c);border:1px solid #293b54;border-radius:18px;padding:18px;box-shadow:0 12px 35px #0002}.game{transition:.2s;cursor:pointer}.game:hover{transform:translateY(-4px);border-color:var(--mint)}.icon{font-size:30px}.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.between{justify-content:space-between}.pill{display:inline-block;border-radius:30px;padding:4px 9px;background:#163c39;color:var(--mint);font-size:11px;font-weight:800}.hidden{display:none!important}.section{margin-top:28px}.section h2{font-size:23px}.stat{font-size:27px;font-weight:900;color:var(--mint)}.modal{position:fixed;inset:0;background:#000b;z-index:10;display:grid;place-items:center;padding:15px}.modalbox{width:min(560px,100%);max-height:90vh;overflow:auto;background:#111b2c;border:1px solid #3b526c;border-radius:20px;padding:22px}.formgrid{display:grid;grid-template-columns:1fr 1fr;gap:0 12px}.toast{position:fixed;right:20px;bottom:20px;background:#172b3b;border:1px solid var(--mint);padding:13px 18px;border-radius:12px;z-index:20;max-width:90vw}.otp{display:flex;gap:8px}.otp input{text-align:center;font-size:24px;font-weight:900}.gameplay{background:#091321;border-radius:15px;padding:22px;text-align:center;margin:15px 0}.big{font-size:38px;font-weight:950;color:var(--gold)}footer{border-top:1px solid #24344a;margin-top:45px;padding:25px;color:var(--muted);text-align:center}.notice{border:1px solid #69552c;background:#2a2416;color:#f5d58a;padding:12px;border-radius:12px;font-size:13px}@media(max-width:650px){.hero{padding:24px;display:block}.nav{align-items:flex-start;flex-direction:column}.formgrid{grid-template-columns:1fr}.wrap{padding:0 13px}.otp{gap:4px}.otp input{padding:10px 2px}}
</style></head><body>
<header class="top"><div class="nav"><div class="brand">BETTING <b>WORLD</b></div><div class="navlinks"><button onclick="showPage('home')">Home</button><button onclick="showPage('games')">Games</button><button onclick="showPage('sports')">Sports</button><button onclick="showPage('wallet')">Wallet</button><?php if($logged): ?><button onclick="showPage('profile')">Profile</button><button onclick="logout()">Logout</button><?php else: ?><button onclick="openModal('loginModal')">Login</button><button onclick="openModal('registerModal')">Join now</button><?php endif; ?></div></div></header>
<main class="wrap">
<div class="notice">DEMO MODE ONLY · 18+ · Credits are fictional, non-transferable and have no cash value. No deposits, cash-outs or real-money wagering are available.</div>
<section id="homePage" class="page"><div class="hero"><div><span class="pill">WELCOME TO BETTING WORLD</span><h1>ENTER THE WORLD<br>OF <span>GAMING.</span></h1><p class="muted">Explore 15 interactive games, sports demos and a play-credit wallet.</p><div class="row"><?php if(!$logged): ?><button onclick="openModal('registerModal')">Create account</button><button class="secondary" onclick="openModal('loginModal')">Sign in</button><?php else: ?><button onclick="showPage('games')">Explore games</button><?php endif; ?></div></div><div style="font-size:100px">🎮</div></div>
<div id="dashboard" class="section"></div><div class="section"><h2>Popular games</h2><div id="popularGames" class="grid"></div></div></section>
<section id="gamesPage" class="page hidden"><h2>Gaming lobby</h2><p class="muted">Choose a game. Each round is a server-generated demo result.</p><div id="allGames" class="grid"></div></section>
<section id="sportsPage" class="page hidden"><h2>Sports centre</h2><p class="muted">All fixtures and scores below are sample data, not live events.</p><div id="sportsList" class="grid"></div></section>
<section id="walletPage" class="page hidden"><h2>Demo wallet</h2><div class="card"><div class="muted">Available play credits</div><div id="walletBalance" class="stat">—</div><p class="muted">No monetary value. Withdrawals and real-money deposits are disabled.</p><button onclick="demoReset()">Refresh demo credits</button></div><div id="walletHistory" class="section"></div></section>
<section id="profilePage" class="page hidden"><h2>My profile</h2><div class="card"><form onsubmit="saveProfile(event)"><label>Full name</label><input name="full_name" id="profileName" required><label>Mobile</label><input name="mobile" id="profileMobile" required maxlength="10"><button>Save profile</button></form><hr style="border-color:#293b54;margin:24px 0"><h3>Change password</h3><form onsubmit="changePassword(event)"><label>Current password</label><input name="current_password" type="password" required><label>New password</label><input name="new_password" type="password" minlength="10" required><button>Update password</button></form></div><div class="card section"><h3>Support centre</h3><form onsubmit="sendSupport(event)"><label>Subject</label><input name="subject" required><label>Message</label><textarea name="message" rows="4" required></textarea><button>Submit ticket</button></form></div></section>
</main><footer>BETTING WORLD · ENTER THE WORLD OF GAMING<br>18+ only · Demo entertainment · Play responsibly</footer>
<div id="gameModal" class="modal hidden" onclick="if(event.target===this)closeModal('gameModal')"><div class="modalbox"><div class="row between"><h2 id="gameTitle">Game</h2><button class="secondary" onclick="closeModal('gameModal')">✕</button></div><p id="gameDescription" class="muted"></p><div class="gameplay"><div id="gameVisual" class="big">🎲</div><p id="gameResult" class="muted">Ready for a demo round?</p></div><label>Your selection (optional)</label><input id="gameChoice" placeholder="Enter a colour, number or choice"><button style="width:100%;margin-top:12px" onclick="playRound()">Play demo round</button><p class="muted" style="font-size:12px">This is a random demo simulation. No credits are wagered or won.</p></div></div>
<div id="registerModal" class="modal hidden"><div class="modalbox"><div class="row between"><h2>Create account</h2><button class="secondary" onclick="closeModal('registerModal')">✕</button></div><form id="registerForm" onsubmit="register(event)"><div class="formgrid"><div><label>Full name</label><input name="full_name" required></div><div><label>Username</label><input name="username" pattern="[A-Za-z0-9_]{3,24}" required></div><div><label>Email</label><input name="email" type="email" required></div><div><label>Mobile number</label><input name="mobile" maxlength="10" required></div><div><label>Date of birth</label><input name="dob" type="date" required></div><div><label>Password</label><input name="password" type="password" minlength="10" required></div></div><label>Confirm password</label><input name="confirm_password" type="password" minlength="10" required><p class="muted" style="font-size:12px">18+ only. By registering you accept the demo terms and responsible-play rules.</p><button style="width:100%">Register & verify email</button></form></div></div>
<div id="otpModal" class="modal hidden"><div class="modalbox"><h2>Verify your email</h2><p id="otpInfo" class="muted">Enter the six-digit code sent to your email.</p><form onsubmit="verifyOtp(event)"><div class="otp"><input maxlength="1" inputmode="numeric"><input maxlength="1" inputmode="numeric"><input maxlength="1" inputmode="numeric"><input maxlength="1" inputmode="numeric"><input maxlength="1" inputmode="numeric"><input maxlength="1" inputmode="numeric"></div><button style="width:100%;margin-top:18px">Verify OTP</button></form><p class="muted">Code expires in five minutes. Request limits apply.</p></div></div>
<div id="loginModal" class="modal hidden"><div class="modalbox"><div class="row between"><h2>Sign in</h2><button class="secondary" onclick="closeModal('loginModal')">✕</button></div><form onsubmit="login(event)"><label>Username or email</label><input name="identity" required><label>Password</label><input name="password" type="password" required><button style="width:100%;margin-top:15px">Continue with email OTP</button></form><hr style="border-color:#293b54;margin:20px 0"><h3>Email OTP login</h3><form onsubmit="otpLoginRequest(event)"><label>Registered email</label><input name="email" type="email" required><button class="secondary" style="width:100%;margin-top:12px">Send login OTP</button></form><p><button class="secondary" onclick="openForgot()">Forgot password?</button></p></div></div>
<div id="forgotModal" class="modal hidden"><div class="modalbox"><h2>Reset password</h2><form onsubmit="forgotRequest(event)"><label>Registered email</label><input name="email" type="email" required><button>Send reset OTP</button></form><form class="hidden" id="resetForm" onsubmit="forgotReset(event)"><label>OTP</label><input name="otp" maxlength="6" required><label>New password</label><input name="password" type="password" minlength="10" required><label>Confirm password</label><input name="confirm_password" type="password" minlength="10" required><button>Reset password</button></form></div></div>
<div id="toast" class="toast hidden"></div>
<script>
const CSRF=<?=json_encode($csrfToken)?>, IS_LOGGED=<?= $logged?'true':'false' ?>;
let pendingEmail='',otpPurpose='register',currentGame=0,games=[];
function toast(s){let t=document.getElementById('toast');t.textContent=s;t.classList.remove('hidden');setTimeout(()=>t.classList.add('hidden'),3500)}
function openModal(id){document.getElementById(id).classList.remove('hidden')}function closeModal(id){document.getElementById(id).classList.add('hidden')}
function showPage(p){document.querySelectorAll('.page').forEach(x=>x.classList.add('hidden'));document.getElementById(p+'Page').classList.remove('hidden');if(p==='wallet')loadDashboard();if(p==='sports')loadSports()}
async function api(action,data={}){let fd=new FormData();Object.entries(data).forEach(([k,v])=>fd.append(k,v));let r=await fetch('?api='+action,{method:'POST',headers:{'X-CSRF-TOKEN':CSRF},body:fd});let j=await r.json();if(!j.ok)throw new Error(j.message||'Request failed');return j}
function otpBoxes(){let boxes=[...document.querySelectorAll('.otp input')];boxes.forEach((b,i)=>{b.oninput=()=>{b.value=b.value.replace(/\D/g,'').slice(0,1);if(b.value&&boxes[i+1])boxes[i+1].focus()};b.onkeydown=e=>{if(e.key==='Backspace'&&!b.value&&boxes[i-1])boxes[i-1].focus()};b.onpaste=e=>{let s=e.clipboardData.getData('text').replace(/\D/g,'').slice(0,6);boxes.forEach((x,k)=>x.value=s[k]||'');boxes[Math.min(s.length,5)].focus();e.preventDefault()}})}
otpBoxes();
async function register(ev){ev.preventDefault();let d=Object.fromEntries(new FormData(ev.target));try{let j=await api('register',d);pendingEmail=j.email;otpPurpose='register';closeModal('registerModal');openModal('otpModal');document.getElementById('otpInfo').textContent='A code was sent to '+j.email;toast(j.message)}catch(e){toast(e.message)}}
async function login(ev){ev.preventDefault();try{let j=await api('login',Object.fromEntries(new FormData(ev.target)));pendingEmail=j.email;otpPurpose='login';closeModal('loginModal');openModal('otpModal');document.getElementById('otpInfo').textContent='Login code sent to '+j.email;toast(j.message)}catch(e){toast(e.message)}}
async function otpLoginRequest(ev){ev.preventDefault();try{let j=await api('otp_login_request',Object.fromEntries(new FormData(ev.target)));pendingEmail=j.email;otpPurpose='otp_login';closeModal('loginModal');openModal('otpModal');toast(j.message)}catch(e){toast(e.message)}}
async function verifyOtp(ev){ev.preventDefault();let otp=[...document.querySelectorAll('.otp input')].map(x=>x.value).join('');try{let j=await api(otpPurpose==='register'?'verify_register':'verify_login',{email:pendingEmail,otp,purpose:otpPurpose});toast(j.message);closeModal('otpModal');if(otpPurpose==='register')openModal('loginModal');else location.reload()}catch(e){toast(e.message)}}
function openForgot(){closeModal('loginModal');openModal('forgotModal)}
async function forgotRequest(ev){ev.preventDefault();try{let j=await api('forgot_request',Object.fromEntries(new FormData(ev.target)));document.getElementById('resetForm').classList.remove('hidden');toast(j.message)}catch(e){toast(e.message)}}
async function forgotReset(ev){ev.preventDefault();try{let j=await api('forgot_reset',Object.fromEntries(new FormData(ev.target)));toast(j.message);closeModal('forgotModal');openModal('loginModal')}catch(e){toast(e.message)}}
async function logout(){try{await api('logout')}finally{location.reload()}}
async function loadGames(){try{let j=await api('games');games=j.games;let html=games.map(g=>`<div class="card game" onclick="openGame(${g.id})"><div class="icon">${g.icon||'🎮'}</div><h3>${esc(g.name)}</h3><p class="muted">${esc(g.description)}</p><span class="pill">${esc(g.category)}</span></div>`).join('');document.getElementById('allGames').innerHTML=html;document.getElementById('popularGames').innerHTML=html.slice(0,1000)}catch(e){toast(e.message)}}
function esc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function openGame(id){if(!IS_LOGGED){openModal('loginModal');return}let g=games.find(x=>+x.id===id);if(!g)return;currentGame=id;document.getElementById('gameTitle').textContent=g.name;document.getElementById('gameDescription').textContent=g.description;document.getElementById('gameVisual').textContent=g.icon||'🎮';document.getElementById('gameResult').textContent='Ready for a demo round?';document.getElementById('gameChoice').value='';openModal('gameModal')}
async function playRound(){try{let j=await api('play',{game_id:currentGame,choice:document.getElementById('gameChoice').value});document.getElementById('gameResult').textContent=j.result.result;document.getElementById('gameVisual').textContent='✨';toast(j.message);loadDashboard()}catch(e){toast(e.message)}}
async function loadDashboard(){if(!IS_LOGGED)return;try{let j=await api('dashboard');let d=document.getElementById('dashboard');d.innerHTML=`<div class="grid"><div class="card"><div class="muted">Demo balance</div><div class="stat">${Number(j.balance).toLocaleString()}</div></div><div class="card"><div class="muted">Games played</div><div class="stat">${j.stats.total||0}</div></div><div class="card"><div class="muted">Account</div><div class="stat" style="font-size:20px">Verified ✓</div></div></div><div class="card"><h3>Welcome, ${esc(j.user.full_name)}</h3><p class="muted">@${esc(j.user.username)} · ${esc(j.user.email)}</p><button onclick="showPage('games')">Play demo games</button></div>`;document.getElementById('walletBalance').textContent=Number(j.balance).toLocaleString()+' credits';document.getElementById('walletHistory').innerHTML='<h3>Recent transactions</h3>'+j.transactions.map(t=>`<div class="card" style="margin:8px 0"><b>${esc(t.type)}</b> · ${esc(t.amount)} credits <span class="muted">· ${esc(t.created_at)}</span><p class="muted">${esc(t.note)}</p></div>`).join('');document.getElementById('profileName').value=j.user.full_name;document.getElementById('profileMobile').value=j.user.mobile}catch(e){toast(e.message)}}
async function demoReset(){try{let j=await api('demo_reset');toast(j.message);loadDashboard()}catch(e){toast(e.message)}}
async function saveProfile(e){e.preventDefault();try{let j=await api('profile',{full_name:e.target.full_name.value,mobile:e.target.mobile.value});toast(j.message)}catch(x){toast(x.message)}}
async function changePassword(e){e.preventDefault();try{let j=await api('change_password',Object.fromEntries(new FormData(e.target)));toast(j.message);e.target.reset()}catch(x){toast(x.message)}}
async function sendSupport(e){e.preventDefault();try{let j=await api('support',Object.fromEntries(new FormData(e.target)));toast(j.message);e.target.reset()}catch(x){toast(x.message)}}
async function loadSports(){try{let j=await api('sports');document.getElementById('sportsList').innerHTML=j.matches.map(m=>`<div class="card"><span class="pill">${esc(m.sport)}</span><h3>${esc(m.home_team)} <span class="muted">vs</span> ${esc(m.away_team)}</h3><p class="muted">${esc(m.match_date)} · ${esc(m.status)}</p><b>${esc(m.demo_result||'Sample fixture')}</b><p class="muted">DEMO DATA — not live scores</p></div>`).join('')}catch(e){toast(e.message)}}
loadGames();if(IS_LOGGED)loadDashboard();
</script></body></html>
