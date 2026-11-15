<?php
declare(strict_types=1);
/* BETTING WORLD — separate administrator dashboard. Demo-only controls. */
session_name('bw_admin'); ini_set('session.use_strict_mode','1'); ini_set('session.cookie_httponly','1'); ini_set('session.cookie_samesite','Strict');
if(!empty($_SERVER['HTTPS'])&&$_SERVER['HTTPS']!=='off')ini_set('session.cookie_secure','1'); session_start();
const DB_HOST='localhost'; const DB_NAME='betting_world'; const DB_USER='YOUR_DB_USERNAME'; const DB_PASS='YOUR_DB_PASSWORD';
const ADMIN_SETUP_KEY='CHANGE-THIS-TO-A-LONG-RANDOM-ONE-TIME-SECRET';
function db():PDO{static $p=null;if(!$p)$p=new PDO('mysql:host='.DB_HOST.';dbname='.DB_NAME.';charset=utf8mb4',DB_USER,DB_PASS,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_DEFAULT_FETCH_MODE=>PDO::FETCH_ASSOC,PDO::ATTR_EMULATE_PREPARES=>false]);return $p;}
function e($v):string{return htmlspecialchars((string)$v,ENT_QUOTES|ENT_SUBSTITUTE,'UTF-8');}
function csrf():string{if(empty($_SESSION['csrf']))$_SESSION['csrf']=bin2hex(random_bytes(32));return $_SESSION['csrf'];}
function out($a,int $s=200):never{http_response_code($s);header('Content-Type:application/json');echo json_encode($a);exit;}
function audit(int $aid,string $action,string $details=''):void{db()->prepare("INSERT INTO admin_activity_logs(admin_id,action,details,ip_address,created_at) VALUES(?,?,?,?,NOW())")->execute([$aid,$action,$details,substr($_SERVER['REMOTE_ADDR']??'',0,45)]);}
if(isset($_GET['api'])){
 try{
  if($_SERVER['REQUEST_METHOD']==='POST'&&!hash_equals(csrf(),$_SERVER['HTTP_X_CSRF_TOKEN']??''))out(['ok'=>false,'message'=>'CSRF validation failed.'],419);
  $a=$_GET['api'];
  if($a==='setup'){
   $count=(int)db()->query("SELECT COUNT(*) FROM admins")->fetchColumn();
   if($count>0||!hash_equals(ADMIN_SETUP_KEY,$_POST['setup_key']??''))out(['ok'=>false,'message'=>'Setup unavailable or invalid setup key.'],403);
   $name=trim($_POST['username']??'');$email=trim($_POST['email']??'');$pass=$_POST['password']??'';
   if(!preg_match('/^[A-Za-z0-9_]{4,30}$/',$name)||!filter_var($email,FILTER_VALIDATE_EMAIL)||strlen($pass)<14)out(['ok'=>false,'message'=>'Use valid details and a 14+ character password.'],422);
   db()->prepare("INSERT INTO admins(username,email,password_hash,status,created_at) VALUES(?,?,?,'active',NOW())")->execute([$name,$email,password_hash($pass,PASSWORD_DEFAULT)]);
   out(['ok'=>true,'message'=>'Administrator created. Sign in.']);
  }
  if($a==='login'){
   $q=db()->prepare("SELECT * FROM admins WHERE username=? AND status='active'");$q->execute([trim($_POST['username']??'')]);$ad=$q->fetch();
   if(!$ad||!password_verify($_POST['password']??'',$ad['password_hash']))out(['ok'=>false,'message'=>'Invalid administrator credentials.'],401);
   session_regenerate_id(true);$_SESSION['aid']=(int)$ad['id'];audit((int)$ad['id'],'admin_login');out(['ok'=>true]);
  }
  if($a==='logout'){$_SESSION=[];session_regenerate_id(true);out(['ok'=>true]);}
  $aid=(int)($_SESSION['aid']??0);if(!$aid)out(['ok'=>false,'message'=>'Administrator login required.'],401);
  if($a==='overview'){
   $stats=[
    'users'=>(int)db()->query("SELECT COUNT(*) FROM users")->fetchColumn(),
    'active'=>(int)db()->query("SELECT COUNT(*) FROM users WHERE status='active'")->fetchColumn(),
    'suspended'=>(int)db()->query("SELECT COUNT(*) FROM users WHERE status='suspended'")->fetchColumn(),
    'games'=>(int)db()->query("SELECT COUNT(*) FROM games")->fetchColumn(),
    'sessions'=>(int)db()->query("SELECT COUNT(*) FROM game_sessions")->fetchColumn(),
    'credits'=>(float)db()->query("SELECT COALESCE(SUM(amount),0) FROM transactions WHERE type='demo_grant'")->fetchColumn(),
    'tickets'=>(int)db()->query("SELECT COUNT(*) FROM support_tickets WHERE status IN('open','in_progress')")->fetchColumn()
   ];
   $users=db()->query("SELECT id,full_name,username,email,status,email_verified,created_at FROM users ORDER BY id DESC LIMIT 30")->fetchAll();
   $tickets=db()->query("SELECT t.id,t.subject,t.status,t.created_at,u.username FROM support_tickets t JOIN users u ON u.id=t.user_id ORDER BY t.id DESC LIMIT 20")->fetchAll();
   $games=db()->query("SELECT id,name,category,is_enabled FROM games ORDER BY id")->fetchAll();
   $activity=db()->query("SELECT l.action,l.details,l.created_at,a.username FROM admin_activity_logs l LEFT JOIN admins a ON a.id=l.admin_id ORDER BY l.id DESC LIMIT 12")->fetchAll();
   out(['ok'=>true,'stats'=>$stats,'users'=>$users,'tickets'=>$tickets,'games'=>$games,'activity'=>$activity]);
  }
  if($a==='user_status'){
   $id=(int)($_POST['user_id']??0);$status=$_POST['status']??'';
   if(!in_array($status,['active','suspended'],true))out(['ok'=>false,'message'=>'Invalid status.'],422);
   db()->prepare("UPDATE users SET status=? WHERE id=?")->execute([$status,$id]);audit($aid,'user_status',"user=$id status=$status");out(['ok'=>true]);
  }
  if($a==='credit'){
   $id=(int)($_POST['user_id']??0);$amount=(float)($_POST['amount']??0);$reason=trim($_POST['reason']??'');
   if($amount<=0||$amount>10000||strlen($reason)<5)out(['ok'=>false,'message'=>'Enter amount (0–10000) and reason.'],422);
   $p=db();$p->beginTransaction();
   try{$q=$p->prepare("SELECT balance FROM wallets WHERE user_id=? FOR UPDATE");$q->execute([$id]);if($q->fetchColumn()===false)throw new RuntimeException('Wallet not found.');
    $p->prepare("UPDATE wallets SET balance=balance+?,updated_at=NOW() WHERE user_id=?")->execute([$amount,$id]);
    $p->prepare("INSERT INTO transactions(user_id,type,amount,status,reference,note,created_at) VALUES(?,'admin_demo_credit',?,'completed',?,?,NOW())")->execute([$id,$amount,'ADMIN-'.bin2hex(random_bytes(5)),$reason]);
    $p->prepare("INSERT INTO wallet_adjustment_logs(admin_id,user_id,amount,reason,created_at) VALUES(?,?,?,?,NOW())")->execute([$aid,$id,$amount,$reason]);$p->commit();
   }catch(Throwable $t){$p->rollBack();throw $t;}audit($aid,'demo_credit',"user=$id amount=$amount reason=$reason");out(['ok'=>true]);
  }
  if($a==='game_toggle'){
   $id=(int)($_POST['game_id']??0);$enabled=(int)($_POST['enabled']??0)?1:0;db()->prepare("UPDATE games SET is_enabled=? WHERE id=?")->execute([$enabled,$id]);audit($aid,'game_toggle',"game=$id enabled=$enabled");out(['ok'=>true]);
  }
  if($a==='ticket_reply'){
   $id=(int)($_POST['ticket_id']??0);$msg=trim($_POST['message']??'');$status=$_POST['status']??'in_progress';
   if(strlen($msg)<2||!in_array($status,['open','in_progress','resolved','closed'],true))out(['ok'=>false,'message'=>'Invalid reply.'],422);
   db()->prepare("INSERT INTO support_replies(ticket_id,sender_type,sender_id,message,created_at) VALUES(?,'admin',?,?,NOW())")->execute([$id,$aid,$msg]);
   db()->prepare("UPDATE support_tickets SET status=?,updated_at=NOW() WHERE id=?")->execute([$status,$id]);audit($aid,'ticket_reply',"ticket=$id");out(['ok'=>true]);
  }
  if($a==='announcement'){
   $title=trim($_POST['title']??'');$body=trim($_POST['body']??'');if(strlen($title)<3||strlen($body)<5)out(['ok'=>false,'message'=>'Enter title and message.'],422);
   db()->prepare("INSERT INTO notifications(user_id,title,message,is_broadcast,created_at) VALUES(NULL,?,?,1,NOW())")->execute([$title,$body]);audit($aid,'announcement',$title);out(['ok'=>true]);
  }
  out(['ok'=>false,'message'=>'Unknown action.'],404);
 }catch(Throwable $t){error_log('BW ADMIN: '.$t->getMessage());out(['ok'=>false,'message'=>'Server error. Check database configuration.'],500);}
}
$token=csrf();$logged=!empty($_SESSION['aid']);
?><!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>BETTING WORLD — Admin</title><style>
:root{--bg:#080d18;--panel:#111b2c;--card:#172338;--mint:#00d9a5;--gold:#f5b942;--muted:#a7b1c2;--red:#ff4757}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:#fff;font:14px/1.5 Inter,system-ui,Arial}button,input,textarea,select{font:inherit}button{border:0;border-radius:9px;padding:9px 13px;background:var(--mint);font-weight:800;cursor:pointer}input,textarea,select{background:#0b1422;color:white;border:1px solid #34445b;border-radius:8px;padding:10px;width:100%}label{display:block;color:var(--muted);margin:10px 0 5px}.layout{display:grid;grid-template-columns:230px 1fr;min-height:100vh}.side{background:#101a2a;border-right:1px solid #26364b;padding:22px;position:sticky;top:0;height:100vh}.brand{font-size:20px;font-weight:950;margin-bottom:30px}.brand b{color:var(--mint)}.side button{display:block;width:100%;text-align:left;margin:8px 0;background:transparent;color:#a7b1c2}.side button:hover{color:var(--mint);background:#1b2b40}.main{padding:26px;min-width:0}.top{display:flex;justify-content:space-between;align-items:center;gap:12px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(155px,1fr));gap:13px;margin:20px 0}.card{background:linear-gradient(145deg,#192941,#111b2c);border:1px solid #293b54;border-radius:15px;padding:16px;overflow:auto}.muted{color:var(--muted)}.num{font-size:28px;color:var(--mint);font-weight:900}table{width:100%;border-collapse:collapse;min-width:650px}th,td{text-align:left;padding:10px;border-bottom:1px solid #2b3a50}th{color:var(--muted)}.tablewrap{overflow:auto}.section{margin-top:25px}.hidden{display:none!important}.login{max-width:420px;margin:8vh auto;padding:25px;background:var(--panel);border:1px solid #30445e;border-radius:18px}.toast{position:fixed;bottom:20px;right:20px;background:#1c3442;padding:12px 18px;border:1px solid var(--mint);border-radius:10px}@media(max-width:760px){.layout{grid-template-columns:1fr}.side{height:auto;position:static;display:flex;flex-wrap:wrap;padding:12px}.brand{width:100%;margin:0}.side button{width:auto}.main{padding:14px}}
</style></head><body>
<?php if(!$logged): ?><div class="login"><div class="brand">BETTING <b>WORLD</b> / ADMIN</div><div id="loginBox"><h2>Administrator sign in</h2><form onsubmit="login(event)"><label>Username</label><input name="username" required><label>Password</label><input name="password" type="password" required><button style="width:100%;margin-top:16px">Sign in</button></form><p class="muted">No administrator exists? Use first-time setup below.</p><button onclick="document.getElementById('setupBox').classList.remove('hidden')">First-time setup</button></div><div id="setupBox" class="hidden"><h2>Create first administrator</h2><p class="muted">Change ADMIN_SETUP_KEY in admin.php before use. This setup works only while no admin exists.</p><form onsubmit="setup(event)"><label>One-time setup key</label><input name="setup_key" required><label>Username</label><input name="username" required><label>Email</label><input name="email" type="email" required><label>Password (14+ chars)</label><input name="password" type="password" minlength="14" required><button style="width:100%;margin-top:15px">Create admin</button></form></div></div>
<?php else: ?><div class="layout"><aside class="side"><div class="brand">BETTING <b>WORLD</b></div><button onclick="section('overview')">▦ Overview</button><button onclick="section('users')">♙ Customers</button><button onclick="section('games')">🎮 Games</button><button onclick="section('tickets')">✉ Support tickets</button><button onclick="section('announce')">◉ Announcements</button><button onclick="logout()">↪ Logout</button></aside><main class="main"><div class="top"><div><h1 style="margin:0">Admin dashboard</h1><div class="muted">Platform operations · DEMO MODE</div></div><span style="color:var(--mint)">● System online</span></div>
<div id="overview" class="panel"><div id="stats" class="grid"></div><div class="card section"><h3>Recent admin activity</h3><div id="activity" class="tablewrap"></div></div></div>
<div id="users" class="panel hidden"><div class="card"><h2>Customer management</h2><input id="userSearch" placeholder="Search name, username or email" oninput="filterUsers()"><div id="userTable" class="tablewrap section"></div></div></div>
<div id="games" class="panel hidden"><div class="card"><h2>Game management</h2><p class="muted">Enable or disable demo games. No real-money play is supported.</p><div id="gameTable" class="tablewrap"></div></div></div>
<div id="tickets" class="panel hidden"><div class="card"><h2>Support tickets</h2><div id="ticketTable" class="tablewrap"></div></div></div>
<div id="announce" class="panel hidden"><div class="card"><h2>Publish announcement</h2><form onsubmit="announce(event)"><label>Title</label><input name="title" required><label>Message</label><textarea name="body" rows="4" required></textarea><button>Publish</button></form></div></div>
</main></div><?php endif; ?><div id="toast" class="toast hidden"></div>
<script>const CSRF=<?=json_encode($token)?>;let data={users:[]};function toast(s){let t=document.getElementById('toast');t.textContent=s;t.classList.remove('hidden');setTimeout(()=>t.classList.add('hidden'),3500)}
async function api(a,d={}){let f=new FormData();Object.entries(d).forEach(([k,v])=>f.append(k,v));let r=await fetch('?api='+a,{method:'POST',headers:{'X-CSRF-TOKEN':CSRF},body:f});let j=await r.json();if(!j.ok)throw Error(j.message);return j}
async function login(e){e.preventDefault();try{await api('login',Object.fromEntries(new FormData(e.target)));location.reload()}catch(x){toast(x.message)}}
async function setup(e){e.preventDefault();try{let j=await api('setup',Object.fromEntries(new FormData(e.target)));toast(j.message);document.getElementById('setupBox').classList.add('hidden')}catch(x){toast(x.message)}}
async function logout(){await api('logout');location.reload()}
function section(id){document.querySelectorAll('.panel').forEach(x=>x.classList.add('hidden'));document.getElementById(id).classList.remove('hidden')}
function esc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
async function load(){try{let j=await api('overview');data=j;let s=j.stats;document.getElementById('stats').innerHTML=[['Customers',s.users],['Active',s.active],['Suspended',s.suspended],['Games',s.games],['Game sessions',s.sessions],['Demo credits issued',s.credits],['Open tickets',s.tickets]].map(x=>`<div class="card"><div class="muted">${x[0]}</div><div class="num">${Number(x[1]).toLocaleString()}</div></div>`).join('');
document.getElementById('userTable').innerHTML=table(['ID','Customer','Email','Status','Verified','Registered','Actions'],j.users.map(u=>[u.id,esc(u.full_name)+' (@'+esc(u.username)+')',esc(u.email),esc(u.status),u.email_verified?'Yes':'No',esc(u.created_at),`<button onclick="status(${u.id},'${u.status==='active'?'suspended':'active'}')">${u.status==='active'?'Suspend':'Activate'}</button> <button onclick="credit(${u.id})">Issue demo credits</button>`]));
document.getElementById('gameTable').innerHTML=table(['Game','Category','Enabled','Action'],j.games.map(g=>[esc(g.name),esc(g.category),g.is_enabled?'Yes':'No',`<button onclick="toggleGame(${g.id},${g.is_enabled?0:1})">${g.is_enabled?'Disable':'Enable'}</button>`]));
document.getElementById('ticketTable').innerHTML=table(['ID','Customer','Subject','Status','Created','Reply'],j.tickets.map(t=>[t.id,esc(t.username),esc(t.subject),esc(t.status),esc(t.created_at),`<button onclick="reply(${t.id})">Reply</button>`]));
document.getElementById('activity').innerHTML=table(['Admin','Action','Details','Date'],j.activity.map(a=>[esc(a.username||'—'),esc(a.action),esc(a.details),esc(a.created_at)]));}catch(x){toast(x.message)}}
function table(headers,rows){return '<table><thead><tr>'+headers.map(h=>'<th>'+h+'</th>').join('')+'</tr></thead><tbody>'+rows.map(r=>'<tr>'+r.map(c=>'<td>'+c+'</td>').join('')+'</tr>').join('')+'</tbody></table>'}
async function status(id,s){try{await api('user_status',{user_id:id,status:s});toast('Customer status updated.');load()}catch(x){toast(x.message)}}
async function credit(id){let amount=prompt('Demo credits to issue (max 10000):');if(amount===null)return;let reason=prompt('Reason for immutable audit log:');if(!reason)return;try{await api('credit',{user_id:id,amount,reason});toast('Demo credits issued.');load()}catch(x){toast(x.message)}}
async function toggleGame(id,en){try{await api('game_toggle',{game_id:id,enabled:en});load()}catch(x){toast(x.message)}}
async function reply(id){let message=prompt('Reply to customer:');if(!message)return;let status=prompt('Ticket status: open / in_progress / resolved / closed','in_progress');try{await api('ticket_reply',{ticket_id:id,message,status});toast('Reply saved.');load()}catch(x){toast(x.message)}}
async function announce(e){e.preventDefault();try{let j=await api('announcement',Object.fromEntries(new FormData(e.target)));toast(j.message||'Announcement published.');e.target.reset()}catch(x){toast(x.message)}}
function filterUsers(){let q=document.getElementById('userSearch').value.toLowerCase();document.querySelectorAll('#userTable tbody tr').forEach(r=>r.style.display=r.textContent.toLowerCase().includes(q)?'':'none')}
if(document.querySelector('.layout'))load();</script></body></html>
