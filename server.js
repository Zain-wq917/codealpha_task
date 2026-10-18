const express = require('express'), Database = require('better-sqlite3'), crypto = require('crypto');
const db = new Database('zeea.db'); db.pragma('journal_mode=WAL');
db.exec(`
create table if not exists users(id integer primary key,username text unique,pass text,salt text,bio text default '',dp text,cover text,links text default '{}',locked int default 0,active int default 1,privacy text default 'public');
create table if not exists sessions(token text primary key,uid int);
create table if not exists posts(id integer primary key,uid int,caption text,media text,type text,privacy text,ts int);
create table if not exists comments(id integer primary key,pid int,uid int,text text,ts int);
create table if not exists likes(pid int,uid int,primary key(pid,uid));
create table if not exists favs(pid int,uid int,primary key(pid,uid));
create table if not exists follows(a int,b int,primary key(a,b));
create table if not exists friends(a int,b int,status text,primary key(a,b));`);
const app = express(); app.use(express.json({ limit: '60mb' })); app.use(express.static('public'));
const hash = (p, s) => crypto.scryptSync(p, s, 32).toString('hex');
const mk = uid => { const t = crypto.randomBytes(24).toString('hex'); db.prepare('insert into sessions values(?,?)').run(t, uid); return t; };
const auth = (q, s, n) => { const r = db.prepare('select uid from sessions where token=?').get((q.headers.authorization || '').replace('Bearer ', '')); if (!r) return s.status(401).json({ error: 'Please log in' }); q.me = r.uid; n(); };
const one = (sql, ...a) => db.prepare(sql).pluck().get(...a);
const vis = me => `(p.uid=${me} or (p.privacy='public' and u.locked=0) or (p.privacy='friends' and exists(select 1 from friends f where f.status='accepted' and ((f.a=p.uid and f.b=${me}) or (f.a=${me} and f.b=p.uid)))))`;
const POST = me => `select p.id,p.uid,p.caption,p.media,p.type,p.ts,u.username,u.dp,(select count(*) from likes where pid=p.id) likes,(select count(*) from comments where pid=p.id) comments,exists(select 1 from likes where pid=p.id and uid=${me}) liked,exists(select 1 from favs where pid=p.id and uid=${me}) faved from posts p join users u on u.id=p.uid`;

app.post('/api/register', (q, s) => {
  const { username, password } = q.body;
  if (!/^[\w.]{3,20}$/.test(username || '') || (password || '').length < 6) return s.status(400).json({ error: 'Username: 3-20 letters or numbers. Password: 6+ characters.' });
  if (one('select 1 from users where username=?', username)) return s.status(400).json({ error: 'Username already taken' });
  const salt = crypto.randomBytes(8).toString('hex');
  const r = db.prepare('insert into users(username,pass,salt) values(?,?,?)').run(username, hash(password, salt), salt);
  s.json({ token: mk(r.lastInsertRowid) });
});
app.post('/api/login', (q, s) => {
  const u = db.prepare('select * from users where username=?').get(q.body.username || '');
  if (!u || hash(q.body.password || '', u.salt) !== u.pass) return s.status(400).json({ error: 'Wrong username or password' });
  s.json({ token: mk(u.id) });
});
app.get('/api/me', auth, (q, s) => {
  const u = db.prepare('select id,username,bio,dp,cover,links,locked,active,privacy from users where id=?').get(q.me);
  u.links = JSON.parse(u.links); u.requests = one("select count(*) from friends where b=? and status='pending'", q.me); s.json(u);
});
app.put('/api/me', auth, (q, s) => {
  for (const f of ['bio', 'dp', 'cover', 'links', 'locked', 'active', 'privacy']) if (f in q.body) {
    const v = q.body[f]; db.prepare(`update users set ${f}=? where id=?`).run(f === 'links' ? JSON.stringify(v) : typeof v === 'boolean' ? +v : v, q.me);
  } s.json({ ok: 1 });
});
app.get('/api/feed', auth, (q, s) => s.json(db.prepare(`${POST(q.me)} where ${vis(q.me)} ${q.query.type === 'reel' ? "and p.type='reel'" : ''} order by p.id desc limit 50`).all()));
app.post('/api/posts', auth, (q, s) => {
  const { caption, media, type, privacy } = q.body;
  if (!caption && !media) return s.status(400).json({ error: 'Empty post' });
  db.prepare('insert into posts(uid,caption,media,type,privacy,ts) values(?,?,?,?,?,?)').run(q.me, caption || '', media || null, type === 'reel' ? 'reel' : 'photo', ['public', 'friends', 'me'].includes(privacy) ? privacy : 'public', Date.now()); s.json({ ok: 1 });
});
const tog = t => (q, s) => {
  const p = +q.params.id, w = one(`select 1 from ${t} where pid=? and uid=?`, p, q.me);
  db.prepare(w ? `delete from ${t} where pid=? and uid=?` : `insert into ${t} values(?,?)`).run(p, q.me);
  s.json({ on: !w, n: one(`select count(*) from ${t} where pid=?`, p) });
};
app.post('/api/posts/:id/like', auth, tog('likes')); app.post('/api/posts/:id/fav', auth, tog('favs'));
app.get('/api/posts/:id/comments', auth, (q, s) => s.json(db.prepare('select c.text,u.username from comments c join users u on u.id=c.uid where pid=? order by c.id').all(+q.params.id)));
app.post('/api/posts/:id/comments', auth, (q, s) => { if (!(q.body.text || '').trim()) return s.status(400).json({ error: 'Empty comment' }); db.prepare('insert into comments(pid,uid,text,ts) values(?,?,?,?)').run(+q.params.id, q.me, q.body.text.trim(), Date.now()); s.json({ ok: 1 }); });

app.get('/api/users/:id', auth, (q, s) => {
  const me = q.me, id = +q.params.id, u = db.prepare('select id,username,bio,dp,cover,links,locked from users where id=?').get(id);
  if (!u) return s.status(404).json({ error: 'User not found' });
  const fr = db.prepare('select a,status from friends where (a=? and b=?) or (a=? and b=?)').get(me, id, id, me);
  u.rel = id === me ? 'me' : !fr ? 'none' : fr.status === 'accepted' ? 'friends' : fr.a === me ? 'sent' : 'got';
  u.links = JSON.parse(u.links);
  u.followers = one('select count(*) from follows where b=?', id); u.followingN = one('select count(*) from follows where a=?', id);
  u.friendsN = one("select count(*) from friends where status='accepted' and (a=? or b=?)", id, id);
  u.postsN = one('select count(*) from posts where uid=?', id);
  u.following = !!one('select 1 from follows where a=? and b=?', me, id); u.followsMe = !!one('select 1 from follows where a=? and b=?', id, me);
  const open = u.rel === 'me' || u.rel === 'friends' || !u.locked;
  u.posts = open ? db.prepare(`${POST(me)} where p.uid=? and ${vis(me)} order by p.id desc`).all(id) : [];
  s.json(u);
});
app.get('/api/search', auth, (q, s) => s.json(db.prepare('select id,username,dp from users where username like ? and id!=? limit 20').all(`%${q.query.q || ''}%`, q.me)));
app.post('/api/follow/:id', auth, (q, s) => { const id = +q.params.id; if (id === q.me) return s.json({}); const w = one('select 1 from follows where a=? and b=?', q.me, id); db.prepare(w ? 'delete from follows where a=? and b=?' : 'insert into follows values(?,?)').run(q.me, id); s.json({ ok: 1 }); });
app.post('/api/friend/:id', auth, (q, s) => { db.prepare("insert or ignore into friends values(?,?,'pending')").run(q.me, +q.params.id); s.json({ ok: 1 }); });
app.post('/api/friend/:id/confirm', auth, (q, s) => {
  const id = +q.params.id; db.prepare("update friends set status='accepted' where a=? and b=?").run(id, q.me);
  db.prepare('insert or ignore into follows values(?,?)').run(id, q.me); db.prepare('insert or ignore into follows values(?,?)').run(q.me, id); s.json({ ok: 1 });
});
app.delete('/api/friend/:id', auth, (q, s) => { const id = +q.params.id; db.prepare('delete from friends where (a=? and b=?) or (a=? and b=?)').run(id, q.me, q.me, id); s.json({ ok: 1 }); });
app.get('/api/requests', auth, (q, s) => s.json(db.prepare("select u.id,u.username,u.dp from friends f join users u on u.id=f.a where f.b=? and f.status='pending'").all(q.me)));
app.get('/api/suggestions', auth, (q, s) => s.json(db.prepare('select id,username,dp from users where id!=? and id not in (select case when a=? then b else a end from friends where a=? or b=?) limit 20').all(q.me, q.me, q.me, q.me)));
app.get('/api/people', auth, (q, s) => s.json(db.prepare(q.query.kind === 'followers' ? 'select u.id,u.username,u.dp from follows f join users u on u.id=f.a where f.b=?' : 'select u.id,u.username,u.dp from follows f join users u on u.id=f.b where f.a=?').all(q.me)));
app.listen(3000, () => console.log('Zee A running on http://localhost:3000'));
