"""
app.py - 备忘录API服务器（Render.com部署版）
"""
import os
import hashlib
import sqlite3
import uuid
from datetime import datetime, date
from functools import wraps

from flask import Flask, request, jsonify, send_from_directory, g
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# 数据库路径
DB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
os.makedirs(DB_DIR, exist_ok=True)
DB_PATH = os.path.join(DB_DIR, 'memo.db')

SECRET = os.environ.get('SECRET_KEY', 'memo-app-secret-2025')


# ============================================================
#  数据库
# ============================================================
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now','localtime'))
        );
        CREATE TABLE IF NOT EXISTS memos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            content TEXT NOT NULL,
            tag TEXT DEFAULT '待办',
            is_done INTEGER DEFAULT 0,
            remind_time TEXT,
            target_date TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now','localtime')),
            updated_at TEXT,
            is_deleted INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        CREATE INDEX IF NOT EXISTS idx_memos_user ON memos(user_id, target_date);
        CREATE INDEX IF NOT EXISTS idx_memos_deleted ON memos(user_id, is_deleted);
    ''')
    conn.commit()
    conn.close()


# ============================================================
#  工具函数
# ============================================================
def hash_password(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()


def generate_token(user_id, username):
    raw = f'{user_id}:{username}:{SECRET}'
    token = hashlib.md5(raw.encode()).hexdigest()
    return f'{user_id}:{token}'


def verify_token(token):
    try:
        parts = token.split(':')
        if len(parts) != 2:
            return None
        user_id = parts[0]
        db = get_db()
        user = db.execute('SELECT id, username FROM users WHERE id = ?', (user_id,)).fetchone()
        if not user:
            return None
        expected = generate_token(user['id'], user['username'])
        if token == expected:
            return user_id
        return None
    except Exception:
        return None


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            return jsonify({'error': '请先登录'}), 401
        user_id = verify_token(token)
        if not user_id:
            return jsonify({'error': '登录已过期'}), 401
        g.user_id = user_id
        return f(*args, **kwargs)
    return decorated


def rows_to_list(rows):
    return [dict(row) for row in rows]


# ============================================================
#  用户接口
# ============================================================
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    username = (data.get('username') or '').strip()
    password = (data.get('password') or '').strip()

    if not username or not password:
        return jsonify({'error': '用户名和密码不能为空'}), 400
    if len(username) < 2:
        return jsonify({'error': '用户名至少2个字符'}), 400
    if len(password) < 6:
        return jsonify({'error': '密码至少6位'}), 400

    db = get_db()
    exists = db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
    if exists:
        return jsonify({'error': '用户名已被注册'}), 400

    user_id = str(uuid.uuid4())
    pwd_hash = hash_password(password)
    db.execute('INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)',
               (user_id, username, pwd_hash))
    db.commit()

    token = generate_token(user_id, username)
    return jsonify({'message': '注册成功', 'user_id': user_id, 'username': username, 'token': token})


@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = (data.get('username') or '').strip()
    password = (data.get('password') or '').strip()

    if not username or not password:
        return jsonify({'error': '请输入用户名和密码'}), 400

    db = get_db()
    pwd_hash = hash_password(password)
    user = db.execute('SELECT id, username FROM users WHERE username = ? AND password_hash = ?',
                      (username, pwd_hash)).fetchone()

    if not user:
        return jsonify({'error': '用户名或密码错误'}), 401

    token = generate_token(user['id'], user['username'])
    return jsonify({'message': '登录成功', 'user_id': user['id'], 'username': user['username'], 'token': token})


# ============================================================
#  备忘录接口
# ============================================================
@app.route('/api/memos', methods=['GET'])
@login_required
def get_memos():
    db = get_db()
    target_date = request.args.get('date')
    tag = request.args.get('tag')
    status = request.args.get('status')
    keyword = request.args.get('keyword', '')

    query = 'SELECT * FROM memos WHERE user_id = ? AND is_deleted = 0'
    params = [g.user_id]

    if target_date:
        query += ' AND target_date = ?'
        params.append(target_date)
    if tag:
        query += ' AND tag = ?'
        params.append(tag)
    if status == 'done':
        query += ' AND is_done = 1'
    elif status == 'undone':
        query += ' AND is_done = 0'
    if keyword:
        query += ' AND content LIKE ?'
        params.append(f'%{keyword}%')

    query += ' ORDER BY target_date DESC, is_done ASC, created_at DESC'
    rows = db.execute(query, params).fetchall()
    return jsonify(rows_to_list(rows))


@app.route('/api/memos', methods=['POST'])
@login_required
def add_memo():
    data = request.get_json()
    content = (data.get('content') or '').strip()
    if not content:
        return jsonify({'error': '内容不能为空'}), 400

    db = get_db()
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    target_date = data.get('target_date') or date.today().isoformat()

    cursor = db.execute(
        'INSERT INTO memos (user_id, content, tag, remind_time, target_date, created_at) VALUES (?, ?, ?, ?, ?, ?)',
        (g.user_id, content, data.get('tag', '待办'), data.get('remind_time'), target_date, now))
    db.commit()

    memo = db.execute('SELECT * FROM memos WHERE id = ?', (cursor.lastrowid,)).fetchone()
    return jsonify(dict(memo)), 201


@app.route('/api/memos/<int:memo_id>/toggle', methods=['POST'])
@login_required
def toggle_memo(memo_id):
    db = get_db()
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    memo = db.execute('SELECT * FROM memos WHERE id = ? AND user_id = ?', (memo_id, g.user_id)).fetchone()
    if not memo:
        return jsonify({'error': '不存在'}), 404

    new_status = 0 if memo['is_done'] else 1
    db.execute('UPDATE memos SET is_done = ?, updated_at = ? WHERE id = ?', (new_status, now, memo_id))
    db.commit()
    return jsonify({'id': memo_id, 'is_done': new_status})


@app.route('/api/memos/<int:memo_id>', methods=['PUT'])
@login_required
def update_memo(memo_id):
    data = request.get_json()
    db = get_db()
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    memo = db.execute('SELECT * FROM memos WHERE id = ? AND user_id = ?', (memo_id, g.user_id)).fetchone()
    if not memo:
        return jsonify({'error': '不存在'}), 404

    fields = ['updated_at = ?']
    values = [now]
    for field in ['content', 'tag', 'remind_time', 'target_date']:
        if field in data:
            fields.append(f'{field} = ?')
            values.append(data[field])
    if 'is_done' in data:
        fields.append('is_done = ?')
        values.append(1 if data['is_done'] else 0)

    values.append(memo_id)
    db.execute(f"UPDATE memos SET {', '.join(fields)} WHERE id = ?", values)
    db.commit()
    updated = db.execute('SELECT * FROM memos WHERE id = ?', (memo_id,)).fetchone()
    return jsonify(dict(updated))


@app.route('/api/memos/<int:memo_id>', methods=['DELETE'])
@login_required
def delete_memo(memo_id):
    db = get_db()
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    result = db.execute('UPDATE memos SET is_deleted = 1, updated_at = ? WHERE id = ? AND user_id = ?',
                        (now, memo_id, g.user_id))
    db.commit()
    if result.rowcount == 0:
        return jsonify({'error': '不存在'}), 404
    return jsonify({'message': '删除成功'})


@app.route('/api/memos/sync', methods=['POST'])
@login_required
def sync_memos():
    data = request.get_json()
    local_memos = data.get('memos', [])
    db = get_db()
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    cloud_memos = db.execute(
        'SELECT * FROM memos WHERE user_id = ? AND is_deleted = 0', (g.user_id,)
    ).fetchall()

    cloud_keys = set()
    for cm in cloud_memos:
        key = f"{cm['content']}||{cm['target_date']}"
        cloud_keys.add(key)

    uploaded = 0
    for lm in local_memos:
        key = f"{lm.get('content', '')}||{lm.get('target_date', '')}"
        if key not in cloud_keys:
            db.execute(
                'INSERT INTO memos (user_id, content, tag, is_done, remind_time, target_date, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
                (g.user_id, lm.get('content', ''), lm.get('tag', '待办'),
                 1 if lm.get('is_done') else 0, lm.get('remind_time'),
                 lm.get('target_date', date.today().isoformat()), now))
            uploaded += 1
    db.commit()

    all_memos = db.execute(
        'SELECT * FROM memos WHERE user_id = ? AND is_deleted = 0 ORDER BY target_date DESC, created_at DESC',
        (g.user_id,)
    ).fetchall()

    return jsonify({'message': f'同步完成，上传{uploaded}条', 'memos': rows_to_list(all_memos)})


# ============================================================
#  前端页面
# ============================================================
WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')


@app.route('/')
def serve_index():
    return send_from_directory(WEB_DIR, 'index.html')


@app.route('/<path:filename>')
def serve_static(filename):
    return send_from_directory(WEB_DIR, filename)


# ============================================================
#  启动
# ============================================================
init_db()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)