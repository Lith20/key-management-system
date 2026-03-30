
const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const crypto = require('crypto');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

const db = new sqlite3.Database('keys.db');

db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT UNIQUE,
            type TEXT,
            days INTEGER,
            expiry INTEGER,
            status TEXT,
            used_by TEXT,
            device_id TEXT,
            created_at INTEGER,
            used_at INTEGER,
            notes TEXT
        )
    `);
    
    db.run(`
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT,
            key_code TEXT,
            ip TEXT,
            user_agent TEXT,
            timestamp INTEGER
        )
    `);
    
    db.run(`
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            token TEXT
        )
    `);
    
    db.get("SELECT * FROM admins WHERE username = 'admin'", (err, row) => {
        if (!row) {
            db.run("INSERT INTO admins (username, password, token) VALUES (?, ?, ?)",
                ['admin', crypto.createHash('sha256').update('admin123').digest('hex'), crypto.randomBytes(32).toString('hex')]
            );
        }
    });
});

app.post('/api/verify', (req, res) => {
    const { code, device_id } = req.body;
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    
    db.get('SELECT * FROM keys WHERE code = ?', [code], (err, key) => {
        if (err || !key) {
            return res.json({ status: 'error', message: 'Invalid code' });
        }
        
        const now = Date.now();
        
        if (key.status === 'used') {
            return res.json({ status: 'error', message: 'Code already used' });
        }
        
        if (now > key.expiry) {
            db.run('UPDATE keys SET status = ? WHERE code = ?', ['expired', code]);
            return res.json({ status: 'error', message: 'Code expired' });
        }
        
        db.run('UPDATE keys SET status = ?, used_by = ?, device_id = ?, used_at = ? WHERE code = ?',
            ['used', device_id || 'unknown', device_id, now, code]);
        
        res.json({
            status: 'success',
            message: 'Code activated',
            type: key.type,
            days: key.days,
            expiry: key.expiry
        });
    });
});

app.post('/api/admin/login', (req, res) => {
    const { username, password } = req.body;
    const hashed = crypto.createHash('sha256').update(password).digest('hex');
    
    db.get('SELECT * FROM admins WHERE username = ? AND password = ?', [username, hashed], (err, admin) => {
        if (admin) {
            const newToken = crypto.randomBytes(32).toString('hex');
            db.run('UPDATE admins SET token = ? WHERE id = ?', [newToken, admin.id]);
            res.json({ success: true, token: newToken, username: admin.username });
        } else {
            res.status(401).json({ success: false, error: 'Invalid credentials' });
        }
    });
});

function authMiddleware(req, res, next) {
    const token = req.headers['admin-token'];
    if (!token) return res.status(401).json({ error: 'Unauthorized' });
    
    db.get('SELECT * FROM admins WHERE token = ?', [token], (err, admin) => {
        if (err || !admin) return res.status(401).json({ error: 'Invalid token' });
        req.admin = admin;
        next();
    });
}

app.post('/api/admin/generate', authMiddleware, (req, res) => {
    const { count = 1, type = 'premium', days = 30, prefix = '', notes = '' } = req.body;
    
    const generated = [];
    const expiry = Date.now() + (days * 24 * 3600 * 1000);
    
    for (let i = 0; i < count; i++) {
        const random = crypto.randomBytes(12).toString('hex').toUpperCase();
        const code = prefix + random;
        
        db.run('INSERT INTO keys (code, type, days, expiry, status, created_at, notes) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [code, type, days, expiry, 'active', Date.now(), notes]);
        
        generated.push(code);
    }
    
    res.json({ success: true, count: generated.length, keys: generated });
});

app.get('/api/admin/keys', authMiddleware, (req, res) => {
    db.all('SELECT * FROM keys ORDER BY created_at DESC', [], (err, keys) => {
        res.json({ keys: keys || [] });
    });
});

app.get('/api/admin/stats', authMiddleware, (req, res) => {
    db.get(`
        SELECT 
            COUNT(*) as total,
            SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) as active,
            SUM(CASE WHEN status = 'used' THEN 1 ELSE 0 END) as used,
            SUM(CASE WHEN status = 'expired' THEN 1 ELSE 0 END) as expired
        FROM keys
    `, (err, stats) => {
        res.json(stats || { total: 0, active: 0, used: 0, expired: 0 });
    });
});

app.get('/api/admin/logs', authMiddleware, (req, res) => {
    db.all('SELECT * FROM logs ORDER BY timestamp DESC LIMIT 100', [], (err, logs) => {
        res.json(logs || []);
    });
});

app.post('/api/admin/update-key', authMiddleware, (req, res) => {
    const { code, action, days } = req.body;
    
    db.get('SELECT * FROM keys WHERE code = ?', [code], (err, key) => {
        if (!key) return res.status(404).json({ error: 'Code not found' });
        
        if (action === 'extend') {
            const newExpiry = Math.max(key.expiry, Date.now()) + (days * 24 * 3600 * 1000);
            db.run('UPDATE keys SET expiry = ?, status = ? WHERE code = ?', [newExpiry, 'active', code]);
            res.json({ success: true });
        } else if (action === 'disable') {
            db.run('UPDATE keys SET status = ? WHERE code = ?', ['disabled', code]);
            res.json({ success: true });
        }
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));