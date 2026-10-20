#!/usr/bin/env python3
"""FrameFlow production-minded local application server (Python stdlib + SQLite)."""
from __future__ import annotations
import argparse, hashlib, hmac, json, os, secrets, sqlite3, time, uuid, traceback
from contextlib import contextmanager
from datetime import date, datetime, timedelta
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

ROOT = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get('FRAMEFLOW_DATA_DIR', str(ROOT / 'data')))
DB_PATH = DATA_DIR / 'frameflow.sqlite3'
COOKIE = 'frameflow_session'
SESSION_SECONDS = 60 * 60 * 12
PBKDF2_ROUNDS = 310_000
CENTS = Decimal('0.01')


def connect():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(DB_PATH, timeout=15)
    c.row_factory = sqlite3.Row
    c.execute('PRAGMA foreign_keys=ON')
    c.execute('PRAGMA journal_mode=WAL')
    return c


def init_db():
    with connect() as c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE COLLATE NOCASE, password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('Administrator','Estimator','Sales','Viewer')), active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, expires_at INTEGER NOT NULL, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS clients(id TEXT PRIMARY KEY, name TEXT NOT NULL, phone TEXT NOT NULL, email TEXT NOT NULL DEFAULT '', address TEXT NOT NULL DEFAULT '', notes TEXT NOT NULL DEFAULT '', archived INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS products(id TEXT PRIMARY KEY, code TEXT NOT NULL UNIQUE COLLATE NOCASE, name TEXT NOT NULL, category TEXT NOT NULL, unit TEXT NOT NULL, rate TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS rate_history(id TEXT PRIMARY KEY, product_id TEXT NOT NULL REFERENCES products(id), rate TEXT NOT NULL, currency TEXT NOT NULL, unit TEXT NOT NULL, effective_at TEXT NOT NULL, actor_id TEXT REFERENCES users(id));
        CREATE TABLE IF NOT EXISTS quotations(id TEXT PRIMARY KEY, number TEXT NOT NULL UNIQUE, revision INTEGER NOT NULL DEFAULT 1, client_id TEXT REFERENCES clients(id), client_name TEXT NOT NULL, client_phone TEXT NOT NULL DEFAULT '', client_email TEXT NOT NULL DEFAULT '', client_address TEXT NOT NULL DEFAULT '', status TEXT NOT NULL CHECK(status IN ('Draft','Issued','Approved','Rejected','Expired')), currency TEXT NOT NULL, valid_until TEXT NOT NULL DEFAULT '', terms TEXT NOT NULL DEFAULT '', subtotal TEXT NOT NULL, discount TEXT NOT NULL, total TEXT NOT NULL, items_json TEXT NOT NULL, snapshot_json TEXT, created_by TEXT REFERENCES users(id), created_at TEXT NOT NULL, updated_at TEXT NOT NULL, issued_at TEXT);
        CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS audit_logs(id TEXT PRIMARY KEY, actor_id TEXT REFERENCES users(id), action TEXT NOT NULL, entity_type TEXT NOT NULL, entity_id TEXT NOT NULL, metadata TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS idx_quotes_created ON quotations(created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_quotes_client ON quotations(client_id);
        CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at DESC);
        ''')
        for k, v in {'company':'Aluminum & Glass','phone':'','currency':'PKR','terms':'This quotation is valid for 15 days. Final dimensions to be verified at site.'}.items():
            c.execute('INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)', (k, v))


def now(): return datetime.now().astimezone().isoformat(timespec='seconds')
def uid(): return str(uuid.uuid4())
def hash_password(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, PBKDF2_ROUNDS)
    return f'pbkdf2_sha256${PBKDF2_ROUNDS}${salt.hex()}${derived.hex()}'
def verify_password(password, encoded):
    try:
        alg, rounds, salt, digest = encoded.split('$')
        if alg != 'pbkdf2_sha256': return False
        check = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), int(rounds)).hex()
        return hmac.compare_digest(check, digest)
    except Exception: return False
def money(value):
    try: n = Decimal(str(value))
    except (InvalidOperation, ValueError): raise ValueError('Enter a valid amount')
    if not n.is_finite() or n < 0 or n > Decimal('999999999999'): raise ValueError('Amount must be non-negative and within supported range')
    return n.quantize(CENTS, rounding=ROUND_HALF_UP)
def row_dict(r): return dict(r) if r else None

def session_cookie(token, max_age):
    secure = '; Secure' if os.environ.get('FRAMEFLOW_SECURE_COOKIES', '').lower() in ('1', 'true', 'yes') else ''
    return f'{COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={max_age}{secure}'

class Handler(BaseHTTPRequestHandler):
    server_version = 'FrameFlow/1.0'
    def log_message(self, fmt, *args):
        # Avoid logging request bodies, credentials, or personal data.
        if self.path.startswith('/api/auth'): return
        super().log_message(fmt, *args)
    def send_json(self, code, data, extra=None):
        payload = json.dumps(data, ensure_ascii=False, separators=(',', ':')).encode()
        self.send_response(code); self.send_header('Content-Type','application/json; charset=utf-8'); self.send_header('Content-Length',str(len(payload))); self.send_header('Cache-Control','no-store'); self.send_header('X-Content-Type-Options','nosniff'); self.send_header('Content-Security-Policy',"default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; script-src 'self'; img-src 'self' data:")
        for k,v in (extra or {}).items(): self.send_header(k,v)
        self.end_headers(); self.wfile.write(payload)
    def body(self):
        try:
            n=int(self.headers.get('Content-Length','0'))
            if n>1_000_000: raise ValueError('Request too large')
            return json.loads(self.rfile.read(n) or b'{}')
        except (json.JSONDecodeError, UnicodeDecodeError): raise ValueError('Invalid JSON request')
    @contextmanager
    def db(self):
        c=connect()
        try:
            yield c
            c.commit()
        except Exception:
            c.rollback()
            raise
        finally:
            c.close()
    def current_user(self, c):
        cookie=SimpleCookie(); cookie.load(self.headers.get('Cookie','')); morsel=cookie.get(COOKIE)
        if not morsel: return None
        token=morsel.value; row=c.execute('SELECT u.id,u.name,u.email,u.role,u.active,s.expires_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?',(hashlib.sha256(token.encode()).hexdigest(),)).fetchone()
        if not row or not row['active'] or row['expires_at'] < int(time.time()): return None
        return dict(row)
    def require(self, user, roles=None):
        if not user: raise PermissionError('Sign in required')
        if roles and user['role'] not in roles: raise PermissionError('This action is not permitted for your role')
    def audit(self,c,user,action,entity,entity_id,meta=None):
        c.execute('INSERT INTO audit_logs VALUES(?,?,?,?,?,?,?)',(uid(),user['id'] if user else None,action,entity,entity_id,json.dumps(meta or {},ensure_ascii=False),now()))
    def origin_check(self):
        origin=self.headers.get('Origin')
        if origin:
            parsed=urlparse(origin)
            host=self.headers.get('Host','')
            if parsed.netloc.lower()!=host.lower(): raise PermissionError('Cross-origin request rejected')
    def do_GET(self): self.dispatch()
    def do_POST(self): self.dispatch()
    def do_PATCH(self): self.dispatch()
    def do_DELETE(self): self.dispatch()
    def dispatch(self):
        p=urlparse(self.path).path
        if not p.startswith('/api/'):
            if p=='/' or p=='/index.html': return self.static('index.html')
            if p in ('/app.js','/style.css','/favicon.ico'): return self.static(p.lstrip('/'))
            return self.send_json(404,{'error':'Not found'})
        try:
            if self.command in ('POST','PATCH','DELETE'): self.origin_check()
            with self.db() as c:
                if p=='/api/auth/setup-status' and self.command=='GET': return self.send_json(200,{'needed':not bool(c.execute('SELECT 1 FROM users LIMIT 1').fetchone())})
                if p=='/api/auth/setup' and self.command=='POST': return self.setup_admin(c)
                if p=='/api/auth/login' and self.command=='POST': return self.login(c)
                if p=='/api/auth/logout' and self.command=='POST': return self.logout(c)
                user=self.current_user(c)
                if p=='/api/auth/me' and self.command=='GET':
                    if not user: return self.send_json(401,{'error':'Sign in required'})
                    return self.send_json(200,{'user':user})
                self.require(user)
                if p=='/api/clients': return self.clients(c,user)
                if p=='/api/products': return self.products(c,user)
                if p=='/api/quotations': return self.quotes(c,user)
                if p.startswith('/api/quotations/'):
                    bits=p.strip('/').split('/'); qid=bits[2]
                    if len(bits)==4 and bits[3]=='issue' and self.command=='POST': return self.issue(c,user,qid)
                    if len(bits)==4 and bits[3]=='status' and self.command=='POST': return self.status(c,user,qid)
                    if len(bits)==4 and bits[3]=='revision' and self.command=='POST': return self.revision(c,user,qid)
                    if len(bits)==3 and self.command=='GET': return self.one_quote(c,user,qid)
                    if len(bits)==3 and self.command=='PATCH': return self.update_quote(c,user,qid)
                if p=='/api/settings': return self.settings(c,user)
                if p=='/api/users': return self.users(c,user)
                if p=='/api/audit': return self.audit_list(c,user)
                if p=='/api/backup' and self.command=='GET': return self.backup(c,user)
                if p=='/api/dashboard' and self.command=='GET': return self.dashboard(c,user)
                return self.send_json(404,{'error':'Not found'})
        except PermissionError as e: self.send_json(403 if str(e)!='Sign in required' else 401,{'error':str(e)})
        except ValueError as e: self.send_json(400,{'error':str(e)})
        except sqlite3.IntegrityError as e: self.send_json(409,{'error':'Record conflicts with an existing record or quotation history'})
        except Exception as e:
            traceback.print_exc()
            self.send_json(500,{'error':'Something went wrong. Please try again.'})
    def static(self,name):
        f=ROOT/name
        if not f.is_file(): return self.send_json(404,{'error':'Not found'})
        data=f.read_bytes(); typ='text/html; charset=utf-8' if name.endswith('.html') else 'text/javascript; charset=utf-8' if name.endswith('.js') else 'text/css; charset=utf-8'
        self.send_response(200); self.send_header('Content-Type',typ); self.send_header('Content-Length',str(len(data))); self.send_header('X-Content-Type-Options','nosniff'); self.end_headers(); self.wfile.write(data)
    def login(self,c):
        addr=self.client_address[0]; nowt=time.time(); bucket=self.server.login_attempts.setdefault(addr,[]); bucket[:]=[t for t in bucket if nowt-t<300]
        if len(bucket)>=10: return self.send_json(429,{'error':'Too many attempts. Wait five minutes and try again.'})
        d=self.body(); email=str(d.get('email','')).strip().lower(); password=str(d.get('password',''))
        row=c.execute('SELECT * FROM users WHERE email=?',(email,)).fetchone()
        if not row or not row['active'] or not verify_password(password,row['password_hash']):
            bucket.append(nowt); return self.send_json(401,{'error':'Email or password is incorrect'})
        token=secrets.token_urlsafe(32); c.execute('INSERT INTO sessions VALUES(?,?,?,?)',(hashlib.sha256(token.encode()).hexdigest(),row['id'],int(nowt+SESSION_SECONDS),now()))
        user={'id':row['id'],'name':row['name'],'email':row['email'],'role':row['role'],'active':row['active']}; self.audit(c,user,'sign_in','user',user['id'])
        return self.send_json(200,{'user':user},{'Set-Cookie':session_cookie(token, SESSION_SECONDS)})
    def setup_admin(self,c):
        if c.execute('SELECT 1 FROM users LIMIT 1').fetchone(): return self.send_json(409,{'error':'Administrator setup has already been completed'})
        d=self.body();name=str(d.get('name','')).strip();email=str(d.get('email','')).strip().lower();password=str(d.get('password',''))
        if not name or '@' not in email or len(password)<12: raise ValueError('Enter a name, valid email, and password with at least 12 characters')
        x=uid();c.execute('INSERT INTO users VALUES(?,?,?,?,?,?,?)',(x,name,email,hash_password(password),'Administrator',1,now()))
        user={'id':x,'name':name,'email':email,'role':'Administrator','active':1};self.audit(c,user,'initial_admin_created','user',x)
        token=secrets.token_urlsafe(32);c.execute('INSERT INTO sessions VALUES(?,?,?,?)',(hashlib.sha256(token.encode()).hexdigest(),x,int(time.time()+SESSION_SECONDS),now()))
        return self.send_json(201,{'user':user},{'Set-Cookie':session_cookie(token, SESSION_SECONDS)})
    def logout(self,c):
        user=self.current_user(c)
        if user:
            cookie=SimpleCookie(); cookie.load(self.headers.get('Cookie','')); token=cookie[COOKIE].value;c.execute('DELETE FROM sessions WHERE token_hash=?',(hashlib.sha256(token.encode()).hexdigest(),));self.audit(c,user,'sign_out','user',user['id'])
        return self.send_json(200,{'ok':True},{'Set-Cookie':session_cookie('', 0)})
    def clients(self,c,u):
        if self.command=='GET': return self.send_json(200,[dict(x) for x in c.execute('SELECT * FROM clients WHERE archived=0 ORDER BY name COLLATE NOCASE')])
        if self.command=='POST':
            self.require(u,('Administrator','Estimator','Sales'));d=self.body();name=str(d.get('name','')).strip();phone=str(d.get('phone','')).strip()
            if not name or not phone: raise ValueError('Client name and phone are required')
            x=uid();t=now();c.execute('INSERT INTO clients VALUES(?,?,?,?,?,?,?,?,?)',(x,name,phone,str(d.get('email','')).strip(),str(d.get('address','')).strip(),str(d.get('notes','')).strip(),0,t,t));self.audit(c,u,'client_created','client',x)
            return self.send_json(201,dict(c.execute('SELECT * FROM clients WHERE id=?',(x,)).fetchone()))
        if self.command=='PATCH':
            self.require(u,('Administrator','Estimator','Sales'));d=self.body();x=d.get('id');row=c.execute('SELECT * FROM clients WHERE id=?',(x,)).fetchone()
            if not row: return self.send_json(404,{'error':'Client not found'})
            vals=[str(d.get(k,row[k])).strip() for k in ('name','phone','email','address','notes')]
            if not vals[0] or not vals[1]: raise ValueError('Client name and phone are required')
            c.execute('UPDATE clients SET name=?,phone=?,email=?,address=?,notes=?,updated_at=? WHERE id=?',(*vals,now(),x));self.audit(c,u,'client_updated','client',x)
            return self.send_json(200,dict(c.execute('SELECT * FROM clients WHERE id=?',(x,)).fetchone()))
        if self.command=='DELETE':
            self.require(u,('Administrator','Estimator','Sales'));x=parse_qs(urlparse(self.path).query).get('id',[''])[0]
            if c.execute('SELECT 1 FROM quotations WHERE client_id=?',(x,)).fetchone(): c.execute('UPDATE clients SET archived=1,updated_at=? WHERE id=?',(now(),x));action='client_archived'
            else:c.execute('DELETE FROM clients WHERE id=?',(x,));action='client_deleted'
            self.audit(c,u,action,'client',x);return self.send_json(200,{'ok':True})
    def products(self,c,u):
        if self.command=='GET': return self.send_json(200,[dict(x) for x in c.execute('SELECT * FROM products WHERE active=1 ORDER BY category,name')])
        self.require(u,('Administrator',));d=self.body()
        if self.command=='POST':
            x=uid();t=now();code=str(d.get('code','')).strip();name=str(d.get('name','')).strip();unit=str(d.get('unit','')).strip();category=str(d.get('category','Other')).strip();rate=str(money(d.get('rate')))
            if not code or not name or not unit: raise ValueError('Product name, code, and unit are required')
            c.execute('INSERT INTO products VALUES(?,?,?,?,?,?,?,?,?)',(x,code,name,category,unit,rate,1,t,t)); self.audit(c,u,'product_created','product',x,{'code':code})
            c.execute('INSERT INTO rate_history VALUES(?,?,?,?,?,?,?)',(uid(),x,rate,self.setting(c,'currency'),unit,t,u['id']))
            return self.send_json(201,dict(c.execute('SELECT * FROM products WHERE id=?',(x,)).fetchone()))
        if self.command=='PATCH':
            x=d.get('id');old=c.execute('SELECT * FROM products WHERE id=?',(x,)).fetchone()
            if not old:return self.send_json(404,{'error':'Product not found'})
            vals=[str(d.get(k,old[k])).strip() for k in ('code','name','category','unit')];rate=str(money(d.get('rate',old['rate'])))
            if not all(vals):raise ValueError('Product code, name, category, and unit are required')
            c.execute('UPDATE products SET code=?,name=?,category=?,unit=?,rate=?,updated_at=? WHERE id=?',(*vals,rate,now(),x));self.audit(c,u,'rate_changed' if rate!=old['rate'] else 'product_updated','product',x,{'old_rate':old['rate'],'new_rate':rate})
            if rate != old['rate']: c.execute('INSERT INTO rate_history VALUES(?,?,?,?,?,?,?)',(uid(),x,rate,self.setting(c,'currency'),vals[3],now(),u['id']))
            return self.send_json(200,dict(c.execute('SELECT * FROM products WHERE id=?',(x,)).fetchone()))
        if self.command=='DELETE':
            x=parse_qs(urlparse(self.path).query).get('id',[''])[0]
            if c.execute('SELECT 1 FROM quotations WHERE items_json LIKE ?',(f'%{x}%',)).fetchone():c.execute('UPDATE products SET active=0,updated_at=? WHERE id=?',(now(),x))
            else:c.execute('DELETE FROM products WHERE id=?',(x,))
            self.audit(c,u,'product_archived','product',x);return self.send_json(200,{'ok':True})
    def quotation_payload(self,c,d,user,existing=None):
        if existing and existing['status']!='Draft': raise ValueError('Issued quotations cannot be edited; create a revision')
        client=c.execute('SELECT * FROM clients WHERE id=? AND archived=0',(d.get('client_id',existing['client_id'] if existing else ''),)).fetchone()
        if not client: raise ValueError('Select an active client')
        submitted=d.get('items',[])
        if not isinstance(submitted,list) or not submitted: raise ValueError('Add at least one line item')
        items=[];subtotal=Decimal('0.00')
        for it in submitted:
            p=c.execute('SELECT * FROM products WHERE id=? AND active=1',(it.get('product_id'),)).fetchone()
            if not p:raise ValueError('Select an active catalog product for every line')
            
            try: qty=Decimal(str(it.get('qty','')))
            except InvalidOperation: raise ValueError('Enter a valid quantity')
            rate=money(it.get('rate',p['rate']))
            if rate != money(p['rate']) and user['role']!='Administrator': raise PermissionError('Only an administrator may override a catalog rate')
            if not qty.is_finite() or qty<=0 or qty>Decimal('999999'):raise ValueError('Quantity must be positive and within supported limits')
            line=(qty*rate).quantize(CENTS,rounding=ROUND_HALF_UP);subtotal+=line
            items.append({'product_id':p['id'],'code':p['code'],'product_name':p['name'],'category':p['category'],'unit':p['unit'],'qty':str(qty.normalize()),'rate':str(rate),'description':str(it.get('description','')).strip()[:500],'line_total':str(line)})
        subtotal=subtotal.quantize(CENTS,rounding=ROUND_HALF_UP);discount=min(subtotal,money(d.get('discount',existing['discount'] if existing else '0')));total=subtotal-discount
        return {'client_id':client['id'],'client_name':client['name'],'client_phone':client['phone'],'client_email':client['email'],'client_address':client['address'],'valid_until':str(d.get('valid_until',existing['valid_until'] if existing else ''))[:10],'terms':str(d.get('terms',existing['terms'] if existing else ''))[:3000],'currency':str(d.get('currency',existing['currency'] if existing else self.setting(c,'currency')))[:8],'subtotal':str(subtotal),'discount':str(discount),'total':str(total),'items':items}
    def quotes(self,c,u):
        if self.command=='GET':
            rows=[dict(x) for x in c.execute('SELECT * FROM quotations ORDER BY created_at DESC')]
            for q in rows:
                raw_items=q.get('items_json','[]');raw_snapshot=q.get('snapshot_json')
                q['items']=json.loads(raw_items or '[]');q['snapshot']=json.loads(raw_snapshot) if raw_snapshot else None
                q.pop('items_json',None);q.pop('snapshot_json',None)
            return self.send_json(200,rows)
        self.require(u,('Administrator','Estimator','Sales'));d=self.body();fields=self.quotation_payload(c,d,u);x=uid();year=date.today().year
        number=f"QT-{year}-{int(time.time()*1000000)%100000000:08d}"
        while c.execute('SELECT 1 FROM quotations WHERE number=?',(number,)).fetchone():number=f"QT-{year}-{secrets.randbelow(100000000):08d}"
        t=now();items=json.dumps(fields.pop('items'),ensure_ascii=False)
        c.execute('INSERT INTO quotations(id,number,revision,client_id,client_name,client_phone,client_email,client_address,status,currency,valid_until,terms,subtotal,discount,total,items_json,snapshot_json,created_by,created_at,updated_at,issued_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',(x,number,1,fields['client_id'],fields['client_name'],fields['client_phone'],fields['client_email'],fields['client_address'],'Draft',fields['currency'],fields['valid_until'],fields['terms'],fields['subtotal'],fields['discount'],fields['total'],items,None,u['id'],t,t,None));self.audit(c,u,'quotation_created','quotation',x,{'number':number})
        return self.send_json(201,self.get_quote(c,x))
    def get_quote(self,c,x):
        q=row_dict(c.execute('SELECT * FROM quotations WHERE id=?',(x,)).fetchone())
        if q:
            raw_items=q.get('items_json','[]');raw_snapshot=q.get('snapshot_json')
            q['items']=json.loads(raw_items or '[]');q['snapshot']=json.loads(raw_snapshot) if raw_snapshot else None
            q.pop('items_json',None);q.pop('snapshot_json',None)
        return q
    def one_quote(self,c,u,x):
        q=self.get_quote(c,x)
        if not q:return self.send_json(404,{'error':'Quotation not found'})
        return self.send_json(200,q)
    def update_quote(self,c,u,x):
        self.require(u,('Administrator','Estimator','Sales'));old=c.execute('SELECT * FROM quotations WHERE id=?',(x,)).fetchone()
        if not old:return self.send_json(404,{'error':'Quotation not found'})
        fields=self.quotation_payload(c,self.body(),u,old);t=now();items=json.dumps(fields.pop('items'),ensure_ascii=False)
        c.execute('UPDATE quotations SET client_id=?,client_name=?,client_phone=?,client_email=?,client_address=?,currency=?,valid_until=?,terms=?,subtotal=?,discount=?,total=?,items_json=?,updated_at=? WHERE id=?',(fields['client_id'],fields['client_name'],fields['client_phone'],fields['client_email'],fields['client_address'],fields['currency'],fields['valid_until'],fields['terms'],fields['subtotal'],fields['discount'],fields['total'],items,t,x));self.audit(c,u,'quotation_draft_updated','quotation',x)
        return self.send_json(200,self.get_quote(c,x))
    def issue(self,c,u,x):
        self.require(u,('Administrator','Estimator','Sales'));q=c.execute('SELECT * FROM quotations WHERE id=?',(x,)).fetchone()
        if not q:return self.send_json(404,{'error':'Quotation not found'})
        if q['status']!='Draft':raise ValueError('Only a draft can be issued')
        issued=now();snap={k:q[k] for k in ('number','revision','client_name','client_phone','client_email','client_address','currency','valid_until','terms','subtotal','discount','total')};snap['items']=json.loads(q['items_json']);snap['issued_at']=issued
        c.execute("UPDATE quotations SET status='Issued',snapshot_json=?,issued_at=?,updated_at=? WHERE id=?",(json.dumps(snap,ensure_ascii=False),issued,issued,x));self.audit(c,u,'quotation_issued','quotation',x,{'number':q['number']})
        return self.send_json(200,self.get_quote(c,x))
    def status(self,c,u,x):
        self.require(u,('Administrator','Estimator','Sales'));d=self.body();new=d.get('status');q=c.execute('SELECT * FROM quotations WHERE id=?',(x,)).fetchone()
        if not q:return self.send_json(404,{'error':'Quotation not found'})
        allowed={'Issued':('Approved','Rejected','Expired')}
        if new not in allowed.get(q['status'],()):raise ValueError('This quotation status transition is not allowed')
        c.execute('UPDATE quotations SET status=?,updated_at=? WHERE id=?',(new,now(),x));self.audit(c,u,'quotation_status_changed','quotation',x,{'from':q['status'],'to':new});return self.send_json(200,self.get_quote(c,x))
    def revision(self,c,u,x):
        self.require(u,('Administrator','Estimator','Sales'));q=self.get_quote(c,x)
        if not q:return self.send_json(404,{'error':'Quotation not found'})
        data={'client_id':q['client_id'],'valid_until':q['valid_until'],'terms':q['terms'],'currency':q['currency'],'discount':q['discount'],'items':[{'product_id':i['product_id'],'qty':i['qty'],'rate':i['rate'],'description':i['description']} for i in q['items']]}
        fields=self.quotation_payload(c,data,u);newid=uid();n=f"QT-{date.today().year}-{secrets.randbelow(100000000):08d}";t=now();items=json.dumps(fields.pop('items'),ensure_ascii=False)
        c.execute('INSERT INTO quotations(id,number,revision,client_id,client_name,client_phone,client_email,client_address,status,currency,valid_until,terms,subtotal,discount,total,items_json,snapshot_json,created_by,created_at,updated_at,issued_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',(newid,n,q['revision']+1,fields['client_id'],fields['client_name'],fields['client_phone'],fields['client_email'],fields['client_address'],'Draft',fields['currency'],fields['valid_until'],fields['terms'],fields['subtotal'],fields['discount'],fields['total'],items,None,u['id'],t,t,None));self.audit(c,u,'quotation_revision_created','quotation',newid,{'replaces':x,'number':n});return self.send_json(201,self.get_quote(c,newid))
    def setting(self,c,k):
        x=c.execute('SELECT value FROM settings WHERE key=?',(k,)).fetchone();return x['value'] if x else ''
    def settings(self,c,u):
        if self.command=='GET':return self.send_json(200,{x['key']:x['value'] for x in c.execute('SELECT * FROM settings')})
        self.require(u,('Administrator',));d=self.body()
        for k in ('company','phone','currency','terms'):
            if k in d:c.execute('INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',(k,str(d[k])[:3000]))
        self.audit(c,u,'settings_updated','settings','company');return self.send_json(200,{x['key']:x['value'] for x in c.execute('SELECT * FROM settings')})
    def users(self,c,u):
        self.require(u,('Administrator',))
        if self.command=='GET':return self.send_json(200,[{k:r[k] for k in ('id','name','email','role','active','created_at')} for r in c.execute('SELECT * FROM users ORDER BY name')])
        d=self.body()
        if self.command=='POST':
            name=str(d.get('name','')).strip();email=str(d.get('email','')).strip().lower();password=str(d.get('password',''));role=d.get('role')
            if not name or '@' not in email or len(password)<12 or role not in ('Administrator','Estimator','Sales','Viewer'):raise ValueError('Provide name, valid email, role, and a password of at least 12 characters')
            x=uid();c.execute('INSERT INTO users VALUES(?,?,?,?,?,?,?)',(x,name,email,hash_password(password),role,1,now()));self.audit(c,u,'user_created','user',x,{'role':role});return self.send_json(201,{'id':x,'name':name,'email':email,'role':role,'active':1})
        if self.command=='PATCH':
            x=d.get('id');role=d.get('role');active=1 if d.get('active',True) else 0
            if role not in ('Administrator','Estimator','Sales','Viewer'):raise ValueError('Select a valid role')
            if x==u['id'] and not active:raise ValueError('You cannot deactivate your own account')
            current=c.execute('SELECT role,active FROM users WHERE id=?',(x,)).fetchone()
            if current and current['role']=='Administrator' and current['active'] and (role!='Administrator' or not active) and c.execute("SELECT COUNT(*) n FROM users WHERE role='Administrator' AND active=1").fetchone()['n']<=1: raise ValueError('Keep at least one active administrator account')
            c.execute('UPDATE users SET role=?,active=? WHERE id=?',(role,active,x));self.audit(c,u,'user_permissions_changed','user',x,{'role':role,'active':active});return self.send_json(200,{'ok':True})
    def audit_list(self,c,u):
        self.require(u,('Administrator',));rows=[dict(r) for r in c.execute('SELECT a.id,u.name actor,a.action,a.entity_type,a.entity_id,a.metadata,a.created_at FROM audit_logs a LEFT JOIN users u ON u.id=a.actor_id ORDER BY a.created_at DESC LIMIT 250')]
        for r in rows:r['metadata']=json.loads(r['metadata'])
        return self.send_json(200,rows)
    def dashboard(self,c,u):
        n=lambda s:c.execute('SELECT COUNT(*) n FROM quotations WHERE status=?',(s,)).fetchone()['n']
        val=c.execute("SELECT COALESCE(SUM(CAST(total AS NUMERIC)),0) n FROM quotations WHERE status='Approved'").fetchone()['n']
        recent=[self.get_quote(c,r['id']) for r in c.execute('SELECT id FROM quotations ORDER BY created_at DESC LIMIT 7')]
        return self.send_json(200,{'counts':{'total':c.execute('SELECT COUNT(*) n FROM quotations').fetchone()['n'],'draft':n('Draft'),'issued':n('Issued'),'approved':n('Approved'),'rejected':n('Rejected'),'clients':c.execute('SELECT COUNT(*) n FROM clients WHERE archived=0').fetchone()['n']},'approved_value':str(money(val)),'recent':recent})
    def backup(self,c,u):
        self.require(u,('Administrator',));tables={}
        for t in ('users','clients','products','quotations','settings','audit_logs'):
            cols=[r['name'] for r in c.execute(f'PRAGMA table_info({t})')]
            tables[t]=[{k:r[k] for k in cols if k!='password_hash'} for r in c.execute(f'SELECT * FROM {t}')]
        raw=json.dumps({'format':'frameflow-backup-v1','exported_at':now(),'tables':tables},ensure_ascii=False,indent=2).encode();self.send_response(200);self.send_header('Content-Type','application/json; charset=utf-8');self.send_header('Content-Disposition','attachment; filename="frameflow-backup.json"');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)

def main():
    parser=argparse.ArgumentParser(description='Run FrameFlow quotation management system')
    parser.add_argument('--host',default=os.environ.get('HOST', '127.0.0.1'));parser.add_argument('--port',type=int,default=int(os.environ.get('PORT', '8765')))
    args=parser.parse_args();init_db()
    server=ThreadingHTTPServer((args.host,args.port),Handler);server.login_attempts={}
    print(f'FrameFlow running at http://{args.host}:{args.port}');print(f'Database: {DB_PATH}');print('Press Ctrl+C to stop.')
    try:server.serve_forever()
    except KeyboardInterrupt:print('\nStopping FrameFlow...')
    finally:server.server_close()
if __name__=='__main__':main()


