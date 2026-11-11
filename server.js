'use strict';
/*
 * Backend bảo mật cho Lẩu Việt POS/KDS (chỉ dùng module có sẵn của Node.js).
 *  - Mật khẩu băm bằng scrypt + salt riêng, so sánh timing-safe.
 *  - Phiên đăng nhập: cookie httpOnly + SameSite=Strict, lưu trên server, hết hạn sau 8 giờ.
 *  - Khóa đăng nhập sau 5 lần sai (15 phút).
 *  - Khách quét QR theo từng bàn (token riêng): chỉ xem menu và gửi đơn/yêu cầu đúng bàn của mình.
 *  - Bếp (kitchen): xem và xử lý đơn. Quản lý (admin): toàn quyền.
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');
const UPLOAD_DIR = path.join(DATA_DIR, 'uploads');
const PORT = Number(process.env.PORT) || 3000;
const HTTPS_COOKIE = process.env.COOKIE_SECURE === '1';
const SESSION_TTL = 8 * 60 * 60 * 1000;
const MAX_FAILS = 5;
const LOCK_MS = 15 * 60 * 1000;

const defaultMenu = [
    { id: 'mala', name: 'Lẩu Tứ Xuyên', category: 'hotpot', description: 'Nước lẩu cay nồng, thơm vị hoa tiêu.', price: 189000, icon: 'fa-fire-burner' },
    { id: 'mushroom-broth', name: 'Lẩu Nấm Thanh Ngọt', category: 'hotpot', description: 'Nước dùng ninh rau củ và nấm tự nhiên.', price: 159000, icon: 'fa-bowl-food' },
    { id: 'beef-australia', name: 'Ba Chỉ Bò Úc', category: 'meat', description: 'Thịt bò thái lát mỏng, mềm ngọt.', price: 219000, icon: 'fa-drumstick-bite' },
    { id: 'beef-brisket', name: 'Gầu Bò Mỹ', category: 'meat', description: 'Gầu bò vân mỡ, thích hợp nhúng lẩu.', price: 239000, icon: 'fa-bone' },
    { id: 'shrimp', name: 'Tôm Sú Tươi', category: 'meat', description: 'Tôm sú tươi, sơ chế sạch.', price: 189000, icon: 'fa-shrimp' },
    { id: 'fish-ball', name: 'Viên Cá Thác Lác', category: 'meat', description: 'Viên cá dai ngon, làm trong ngày.', price: 99000, icon: 'fa-fish' },
    { id: 'mushroom-set', name: 'Đĩa Nấm Tổng Hợp', category: 'vege', description: 'Nấm kim châm, nấm đùi gà và nấm hương.', price: 89000, icon: 'fa-leaf' },
    { id: 'greens', name: 'Rau Theo Mùa', category: 'vege', description: 'Rau xanh tươi theo ngày.', price: 69000, icon: 'fa-seedling' },
    { id: 'tofu', name: 'Đậu Hũ Non', category: 'vege', description: 'Đậu hũ mềm, dùng kèm nước lẩu.', price: 49000, icon: 'fa-cube' },
    { id: 'beer', name: 'Bia Lạnh', category: 'drinks', description: 'Bia ướp lạnh, phục vụ theo lon.', price: 35000, icon: 'fa-beer-mug-empty' },
    { id: 'tea', name: 'Trà Đào', category: 'drinks', description: 'Trà đào mát lạnh, ít ngọt.', price: 45000, icon: 'fa-mug-hot' },
    { id: 'water', name: 'Nước Suối', category: 'drinks', description: 'Nước suối đóng chai.', price: 20000, icon: 'fa-bottle-water' }
].map(item => ({ ...item, image: `images/${item.id}.jpg` }));

const categoryIcons = { hotpot: 'fa-fire-burner', meat: 'fa-drumstick-bite', vege: 'fa-leaf', drinks: 'fa-mug-hot' };
const paymentMethods = new Set(['cash', 'transfer', 'card']);

/* ---------- Mật khẩu ---------- */
function hashPassword(password, salt = crypto.randomBytes(16)) {
    const hash = crypto.scryptSync(password, salt, 64, { N: 16384, r: 8, p: 1 });
    return { salt: salt.toString('hex'), hash: hash.toString('hex') };
}
function verifyPassword(password, user) {
    const salt = Buffer.from(user ? user.salt : '00'.repeat(16), 'hex');
    const expected = Buffer.from(user ? user.hash : '00'.repeat(64), 'hex');
    const actual = crypto.scryptSync(password, salt, 64, { N: 16384, r: 8, p: 1 });
    return crypto.timingSafeEqual(actual, expected) && Boolean(user);
}
function randomPassword() {
    return crypto.randomBytes(9).toString('base64url');
}
function newToken(bytes = 24) {
    return crypto.randomBytes(bytes).toString('hex');
}

/* ---------- Cơ sở dữ liệu JSON ---------- */
let db;
function createDb() {
    return {
        version: 1,
        nextId: 1,
        users: [],
        tables: ['Bàn 06 - Sân Vườn', 'Bàn 02 - Tầng 1', 'Bàn 08 - Tầng 2', 'Phòng VIP 1 - Máy Lạnh']
            .map(name => ({ name, token: newToken() })),
        customMenuItems: [],
        hiddenMenuItemIds: [],
        orders: [],
        services: [],
        paymentHistory: [],
        recipientAccount: null
    };
}
function persist() {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    const temp = `${DB_FILE}.tmp`;
    fs.writeFileSync(temp, JSON.stringify(db));
    fs.renameSync(temp, DB_FILE);
}
function mutate() {
    db.version += 1;
    persist();
}
function loadDb() {
    fs.mkdirSync(UPLOAD_DIR, { recursive: true });
    db = fs.existsSync(DB_FILE) ? { ...createDb(), ...JSON.parse(fs.readFileSync(DB_FILE, 'utf8')) } : createDb();
    const created = [];
    for (const [username, role] of [['admin', 'admin'], ['bep', 'kitchen']]) {
        if (!db.users.some(user => user.username === username)) {
            const password = randomPassword();
            db.users.push({ username, role, ...hashPassword(password) });
            created.push({ username, role, password });
        }
    }
    persist();
    if (created.length) {
        console.log('\n=== TÀI KHOẢN BAN ĐẦU (chỉ hiện một lần, hãy đổi mật khẩu sau khi đăng nhập) ===');
        created.forEach(item => console.log(`  ${item.role.padEnd(8)} | tài khoản: ${item.username} | mật khẩu: ${item.password}`));
        console.log('================================================================================\n');
    }
}
const allMenu = () => [...defaultMenu, ...db.customMenuItems];

/* ---------- Phiên đăng nhập & chống dò mật khẩu ---------- */
const sessions = new Map();
const failures = new Map();
const rateBuckets = new Map();

function createSession(user) {
    const token = newToken(32);
    sessions.set(token, { username: user.username, role: user.role, expires: Date.now() + SESSION_TTL });
    return token;
}
function parseCookies(header = '') {
    const cookies = {};
    header.split(';').forEach(part => {
        const index = part.indexOf('=');
        if (index > 0) cookies[part.slice(0, index).trim()] = decodeURIComponent(part.slice(index + 1).trim());
    });
    return cookies;
}
function currentSession(req) {
    const token = parseCookies(req.headers.cookie).sid;
    const session = token && sessions.get(token);
    if (!session) return null;
    if (session.expires < Date.now()) {
        sessions.delete(token);
        return null;
    }
    const user = db.users.find(item => item.username === session.username);
    if (!user) return null;
    session.expires = Date.now() + SESSION_TTL;
    return { token, username: user.username, role: user.role };
}
function setCookie(res, value, maxAgeSeconds) {
    res.setHeader('Set-Cookie',
        `sid=${value}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAgeSeconds}${HTTPS_COOKIE ? '; Secure' : ''}`);
}
function rateLimit(key, limit, windowMs) {
    const now = Date.now();
    const bucket = (rateBuckets.get(key) || []).filter(time => now - time < windowMs);
    if (bucket.length >= limit) {
        rateBuckets.set(key, bucket);
        return { allowed: false, retryAfterMs: Math.max(1, bucket[0] + windowMs - now) };
    }
    bucket.push(now);
    rateBuckets.set(key, bucket);
    return { allowed: true, retryAfterMs: 0 };
}
setInterval(() => {
    const now = Date.now();
    sessions.forEach((session, token) => { if (session.expires < now) sessions.delete(token); });
    failures.forEach((entry, key) => { if (entry.lockedUntil < now && now - entry.last > LOCK_MS) failures.delete(key); });
    rateBuckets.forEach((bucket, key) => { if (!bucket.some(time => now - time < 60000)) rateBuckets.delete(key); });
}, 60000).unref();

/* ---------- Tiện ích HTTP ---------- */
class HttpError extends Error {
    constructor(status, message, details = {}) {
        super(message);
        this.status = status;
        this.retryAfterMs = details.retryAfterMs;
    }
}
function send(res, status, body, headers = {}) {
    const payload = typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body);
    res.writeHead(status, {
        'Content-Type': typeof body === 'object' && !Buffer.isBuffer(body) ? 'application/json; charset=utf-8' : 'text/plain; charset=utf-8',
        'Cache-Control': 'no-store',
        ...headers
    });
    res.end(payload);
}
function readJson(req, limit = 1.5 * 1024 * 1024) {
    return new Promise((resolve, reject) => {
        if (!/^application\/json/i.test(req.headers['content-type'] || '')) {
            reject(new HttpError(415, 'Yêu cầu phải là JSON.'));
            return;
        }
        const chunks = [];
        let size = 0;
        req.on('data', chunk => {
            size += chunk.length;
            if (size > limit) {
                reject(new HttpError(413, 'Dữ liệu gửi lên quá lớn.'));
                req.destroy();
                return;
            }
            chunks.push(chunk);
        });
        req.on('end', () => {
            try {
                const value = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
                resolve(value && typeof value === 'object' ? value : {});
            } catch {
                reject(new HttpError(400, 'JSON không hợp lệ.'));
            }
        });
        req.on('error', reject);
    });
}
function requireRole(session, ...roles) {
    if (!session) throw new HttpError(401, 'Bạn cần đăng nhập.');
    if (!roles.includes(session.role)) throw new HttpError(403, 'Bạn không có quyền thực hiện thao tác này.');
}
function guestTable(req) {
    const token = String(req.headers['x-table-token'] || '');
    if (!/^[a-f0-9]{48}$/.test(token)) throw new HttpError(403, 'Mã QR bàn không hợp lệ.');
    const tokenBuffer = Buffer.from(token);
    const table = db.tables.find(item => {
        const candidate = Buffer.from(item.token);
        return candidate.length === tokenBuffer.length && crypto.timingSafeEqual(candidate, tokenBuffer);
    });
    if (!table) throw new HttpError(403, 'Mã QR của bàn này không còn hiệu lực. Vui lòng gọi nhân viên.');
    return table;
}
function vietnamDateKey(timestamp) {
    const parts = new Intl.DateTimeFormat('en-US', {
        timeZone: 'Asia/Ho_Chi_Minh', year: 'numeric', month: '2-digit', day: '2-digit'
    }).formatToParts(new Date(timestamp));
    const values = Object.fromEntries(parts.map(part => [part.type, part.value]));
    return `${values.year}-${values.month}-${values.day}`;
}
function lanOrigin() {
    if (process.env.PUBLIC_URL) return process.env.PUBLIC_URL.replace(/\/$/, '');
    for (const list of Object.values(os.networkInterfaces())) {
        for (const info of list || []) {
            if (info.family === 'IPv4' && !info.internal) return `http://${info.address}:${PORT}`;
        }
    }
    return `http://localhost:${PORT}`;
}
function orderTotal(order) {
    return order.items.reduce((sum, item) => sum + item.price * item.quantity, 0);
}

/* ---------- Trạng thái trả về theo vai trò ---------- */
function buildState(session, guest) {
    const base = {
        version: db.version,
        menu: allMenu(),
        hiddenMenuItemIds: db.hiddenMenuItemIds
    };
    if (guest) {
        return { ...base, role: 'guest', tables: [guest.name], table: guest.name, orders: [], services: [], paymentHistory: [], recipientAccount: null };
    }
    const state = {
        ...base,
        role: session.role,
        username: session.username,
        tables: db.tables.map(table => table.name),
        orders: db.orders,
        services: db.services,
        paymentHistory: [],
        recipientAccount: null
    };
    if (session.role === 'admin') {
        state.paymentHistory = db.paymentHistory;
        state.recipientAccount = db.recipientAccount;
        state.tableLinks = db.tables;
        state.publicUrl = lanOrigin();
    }
    return state;
}

/* ---------- API ---------- */
async function handleApi(req, res, url) {
    const method = req.method;
    const pathname = url.pathname;
    const session = currentSession(req);

    if (method !== 'GET' && method !== 'HEAD') {
        const origin = req.headers.origin;
        if (origin && new URL(origin).host !== req.headers.host) throw new HttpError(403, 'Nguồn yêu cầu không hợp lệ.');
    }

    if (method === 'POST' && pathname === '/api/login') {
        const body = await readJson(req, 4096);
        const username = String(body.username || '').trim().toLowerCase().slice(0, 64);
        const password = String(body.password || '').slice(0, 200);
        const key = `${req.socket.remoteAddress}|${username}`;
        const entry = failures.get(key) || { count: 0, lockedUntil: 0, last: 0 };
        if (entry.lockedUntil > Date.now()) {
            const minutes = Math.ceil((entry.lockedUntil - Date.now()) / 60000);
            throw new HttpError(429, `Đăng nhập sai quá nhiều lần. Hãy thử lại sau ${minutes} phút.`);
        }
        const user = db.users.find(item => item.username === username);
        if (!verifyPassword(password, user)) {
            entry.count += 1;
            entry.last = Date.now();
            if (entry.count >= MAX_FAILS) {
                entry.lockedUntil = Date.now() + LOCK_MS;
                entry.count = 0;
            }
            failures.set(key, entry);
            throw new HttpError(401, 'Sai tài khoản hoặc mật khẩu.');
        }
        failures.delete(key);
        setCookie(res, createSession(user), SESSION_TTL / 1000);
        return send(res, 200, { role: user.role, username: user.username });
    }

    if (method === 'POST' && pathname === '/api/logout') {
        if (session) sessions.delete(session.token);
        setCookie(res, '', 0);
        return send(res, 200, { ok: true });
    }

    if (method === 'GET' && pathname === '/api/me') {
        return send(res, 200, session ? { role: session.role, username: session.username } : { role: null });
    }

    if (method === 'POST' && pathname === '/api/password') {
        requireRole(session, 'admin', 'kitchen');
        const body = await readJson(req, 4096);
        const user = db.users.find(item => item.username === session.username);
        if (!verifyPassword(String(body.current || ''), user)) throw new HttpError(400, 'Mật khẩu hiện tại không đúng.');
        const next = String(body.next || '');
        if (next.length < 8 || next.length > 100) throw new HttpError(400, 'Mật khẩu mới cần từ 8 đến 100 ký tự.');
        Object.assign(user, hashPassword(next));
        sessions.forEach((item, token) => {
            if (item.username === user.username && token !== session.token) sessions.delete(token);
        });
        mutate();
        return send(res, 200, { ok: true });
    }

    if (method === 'GET' && pathname === '/api/state') {
        const guest = session ? null : guestTable(req);
        if (url.searchParams.get('v') === String(db.version) && url.searchParams.get('r') === (session ? session.role : 'guest')) {
            return send(res, 200, { unchanged: true });
        }
        return send(res, 200, buildState(session, guest));
    }

    /* --- Khách (token bàn) --- */
    if (method === 'POST' && pathname === '/api/orders') {
        const table = guestTable(req);
        const orderLimit = rateLimit(`order|${table.token}`, 3, 30000);
        if (!orderLimit.allowed) {
            const seconds = Math.ceil(orderLimit.retryAfterMs / 1000);
            throw new HttpError(429, `Bàn này đã gửi 3 đơn trong 30 giây. Vui lòng đợi ${seconds} giây rồi thử lại.`, orderLimit);
        }
        const body = await readJson(req, 16384);
        if (!Array.isArray(body.items) || !body.items.length || body.items.length > 50) throw new HttpError(400, 'Danh sách món không hợp lệ.');
        const menu = new Map(allMenu().map(item => [item.id, item]));
        const merged = new Map();
        for (const entry of body.items) {
            const id = String(entry && entry.id);
            const quantity = Number(entry && entry.quantity);
            const item = menu.get(id);
            if (!item || db.hiddenMenuItemIds.includes(id)) throw new HttpError(400, 'Có món không còn được bán.');
            if (!Number.isInteger(quantity) || quantity < 1 || quantity > 99) throw new HttpError(400, 'Số lượng món không hợp lệ.');
            merged.set(id, (merged.get(id) || 0) + quantity);
        }
        const items = [...merged].map(([id, quantity]) => ({ name: menu.get(id).name, quantity: Math.min(quantity, 99), price: menu.get(id).price }));
        const order = {
            id: `ORD-${Date.now()}-${db.nextId++}`,
            table: table.name,
            items,
            total: 0,
            status: 'pending',
            createdAt: Date.now()
        };
        order.total = orderTotal(order);
        db.orders.push(order);
        mutate();
        return send(res, 200, { id: order.id, table: order.table, total: order.total });
    }

    if (method === 'POST' && pathname === '/api/services') {
        const table = guestTable(req);
        if (!rateLimit(`service|${table.token}`, 10, 60000).allowed) throw new HttpError(429, 'Bạn gửi yêu cầu quá nhanh.');
        const body = await readJson(req, 2048);
        const request = String(body.request || '').trim().slice(0, 80);
        const allowed = ['Xin thêm nước lẩu', 'Thêm đá lạnh & Trà đá', 'Đổi bát đĩa, muôi lẩu mới', 'Yêu cầu thanh toán tiền bàn'];
        if (!allowed.includes(request)) throw new HttpError(400, 'Yêu cầu không hợp lệ.');
        db.services.push({ id: `SRV-${Date.now()}-${db.nextId++}`, table: table.name, request, createdAt: Date.now(), done: false });
        mutate();
        return send(res, 200, { ok: true });
    }

    /* --- Bếp & quản lý --- */
    let match;
    if (method === 'POST' && (match = pathname.match(/^\/api\/orders\/([\w-]+)\/advance$/))) {
        requireRole(session, 'admin', 'kitchen');
        const order = db.orders.find(item => item.id === match[1]);
        if (!order) throw new HttpError(404, 'Không tìm thấy đơn.');
        order.status = order.status === 'pending' ? 'cooking' : 'done';
        mutate();
        return send(res, 200, { ok: true });
    }
    if (method === 'POST' && (match = pathname.match(/^\/api\/services\/([\w-]+)\/done$/))) {
        requireRole(session, 'admin', 'kitchen');
        const service = db.services.find(item => item.id === match[1]);
        if (!service) throw new HttpError(404, 'Không tìm thấy yêu cầu.');
        service.done = true;
        mutate();
        return send(res, 200, { ok: true });
    }
    if (method === 'POST' && pathname === '/api/orders/clear-done') {
        requireRole(session, 'admin', 'kitchen');
        const before = db.orders.length;
        db.orders = db.orders.filter(order => order.status !== 'done');
        mutate();
        return send(res, 200, { removed: before - db.orders.length });
    }

    /* --- Chỉ quản lý --- */
    if (method === 'POST' && (match = pathname.match(/^\/api\/orders\/([\w-]+)\/pay$/))) {
        requireRole(session, 'admin');
        const body = await readJson(req, 1024);
        const order = db.orders.find(item => item.id === match[1]);
        if (!order) throw new HttpError(404, 'Không tìm thấy đơn.');
        if (!paymentMethods.has(body.method)) throw new HttpError(400, 'Hình thức thanh toán không hợp lệ.');
        if (order.paymentStatus === 'paid') throw new HttpError(409, 'Đơn này đã được ghi nhận thanh toán.');
        const paidAt = Date.now();
        db.paymentHistory.push({
            id: `PAY-${paidAt}-${db.nextId++}`,
            orderId: order.id,
            table: order.table,
            amount: orderTotal(order),
            method: body.method,
            paidAt
        });
        Object.assign(order, { paymentStatus: 'paid', paymentMethod: body.method, paidAt });
        mutate();
        return send(res, 200, { ok: true });
    }
    if (method === 'POST' && pathname === '/api/payments/clear') {
        requireRole(session, 'admin');
        const body = await readJson(req, 1024);
        if (!/^\d{4}-\d{2}-\d{2}$/.test(String(body.date))) throw new HttpError(400, 'Ngày không hợp lệ.');
        const before = db.paymentHistory.length;
        db.paymentHistory = db.paymentHistory.filter(payment => vietnamDateKey(payment.paidAt) !== body.date);
        mutate();
        return send(res, 200, { removed: before - db.paymentHistory.length });
    }
    if (method === 'PUT' && pathname === '/api/recipient') {
        requireRole(session, 'admin');
        const body = await readJson(req, 4096);
        const account = {
            bankName: String(body.bankName || '').trim().slice(0, 80),
            bankBin: String(body.bankBin || '').trim(),
            accountNumber: String(body.accountNumber || '').trim(),
            accountHolder: String(body.accountHolder || '').trim().toUpperCase().slice(0, 100)
        };
        if (!account.bankName || !/^\d{6}$/.test(account.bankBin) || !/^[A-Za-z0-9]{5,25}$/.test(account.accountNumber) || !account.accountHolder) {
            throw new HttpError(400, 'Thông tin tài khoản nhận tiền không hợp lệ.');
        }
        db.recipientAccount = account;
        mutate();
        return send(res, 200, { ok: true });
    }
    if (method === 'PUT' && pathname === '/api/tables') {
        requireRole(session, 'admin');
        const body = await readJson(req, 16384);
        const names = Array.isArray(body.tables) ? body.tables.map(name => String(name).trim()).filter(Boolean) : [];
        if (!names.length || names.length > 100) throw new HttpError(400, 'Cần từ 1 đến 100 bàn.');
        if (names.some(name => name.length > 60)) throw new HttpError(400, 'Tên bàn tối đa 60 ký tự.');
        if (new Set(names.map(name => name.toLocaleLowerCase('vi-VN'))).size !== names.length) throw new HttpError(400, 'Danh sách có tên bàn bị trùng.');
        const existing = new Map(db.tables.map(table => [table.name, table.token]));
        db.tables = names.map(name => ({ name, token: existing.get(name) || newToken() }));
        mutate();
        return send(res, 200, { ok: true });
    }
    if (method === 'POST' && (match = pathname.match(/^\/api\/tables\/regenerate$/))) {
        requireRole(session, 'admin');
        const body = await readJson(req, 1024);
        const table = db.tables.find(item => item.name === body.name);
        if (!table) throw new HttpError(404, 'Không tìm thấy bàn.');
        table.token = newToken();
        mutate();
        return send(res, 200, { ok: true });
    }
    if (method === 'POST' && pathname === '/api/menu') {
        requireRole(session, 'admin');
        const body = await readJson(req);
        const name = String(body.name || '').trim().slice(0, 80);
        const price = Number(body.price);
        const category = String(body.category);
        if (!name || !Number.isFinite(price) || price <= 0 || price > 100000000 || !categoryIcons[category]) {
            throw new HttpError(400, 'Tên món, giá hoặc danh mục không hợp lệ.');
        }
        const id = `custom-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`;
        let image = '';
        const rawImage = String(body.image || '');
        if (rawImage.startsWith('data:image/jpeg;base64,')) {
            const buffer = Buffer.from(rawImage.slice(23), 'base64');
            if (buffer.length > 600 * 1024 || buffer[0] !== 0xff || buffer[1] !== 0xd8) throw new HttpError(400, 'Ảnh tải lên không hợp lệ.');
            fs.mkdirSync(UPLOAD_DIR, { recursive: true });
            fs.writeFileSync(path.join(UPLOAD_DIR, `${id}.jpg`), buffer);
            image = `uploads/${id}.jpg`;
        } else if (/^https?:\/\//i.test(rawImage)) {
            image = new URL(rawImage).href;
        } else if (rawImage) {
            throw new HttpError(400, 'Ảnh không hợp lệ.');
        }
        db.customMenuItems.push({
            id, name, category, price, image,
            description: String(body.description || '').trim().slice(0, 160),
            icon: categoryIcons[category]
        });
        mutate();
        return send(res, 200, { id });
    }
    if (method === 'POST' && (match = pathname.match(/^\/api\/menu\/([\w-]+)\/toggle$/))) {
        requireRole(session, 'admin');
        if (!allMenu().some(item => item.id === match[1])) throw new HttpError(404, 'Không tìm thấy món.');
        db.hiddenMenuItemIds = db.hiddenMenuItemIds.includes(match[1])
            ? db.hiddenMenuItemIds.filter(id => id !== match[1])
            : [...db.hiddenMenuItemIds, match[1]];
        mutate();
        return send(res, 200, { ok: true });
    }

    throw new HttpError(404, 'Không tìm thấy API.');
}

/* ---------- File tĩnh (chỉ whitelist) ---------- */
function serveStatic(req, res, url) {
    let file = null;
    let type = 'application/octet-stream';
    if (url.pathname === '/' || url.pathname === '/index.html') {
        file = path.join(ROOT, 'index.html');
        type = 'text/html; charset=utf-8';
    } else if (/^\/images\/[\w-]+\.jpg$/.test(url.pathname)) {
        file = path.join(ROOT, url.pathname);
        type = 'image/jpeg';
    } else if (/^\/uploads\/[\w-]+\.jpg$/.test(url.pathname)) {
        file = path.join(UPLOAD_DIR, path.basename(url.pathname));
        type = 'image/jpeg';
    }
    if (!file || !fs.existsSync(file)) return send(res, 404, 'Not found');
    res.writeHead(200, {
        'Content-Type': type,
        'Cache-Control': type === 'image/jpeg' ? 'public, max-age=3600' : 'no-store'
    });
    fs.createReadStream(file).pipe(res);
}

/* ---------- Khởi động ---------- */
function resetPasswordCli(username) {
    loadDb();
    const user = db.users.find(item => item.username === username);
    if (!user) {
        console.error(`Không có tài khoản "${username}". Tài khoản hiện có: ${db.users.map(item => item.username).join(', ')}`);
        process.exit(1);
    }
    const password = randomPassword();
    Object.assign(user, hashPassword(password));
    persist();
    console.log(`Mật khẩu mới của "${username}": ${password}`);
}

if (process.argv[2] === 'reset-password') {
    resetPasswordCli(String(process.argv[3] || '').toLowerCase());
} else {
    loadDb();
    const server = http.createServer(async (req, res) => {
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('X-Frame-Options', 'DENY');
        res.setHeader('Referrer-Policy', 'no-referrer');
        try {
            const url = new URL(req.url, 'http://localhost');
            if (url.pathname.startsWith('/api/')) await handleApi(req, res, url);
            else if (req.method === 'GET' || req.method === 'HEAD') serveStatic(req, res, url);
            else send(res, 405, 'Method not allowed');
        } catch (error) {
            if (error instanceof HttpError) {
                const body = { error: error.message };
                const headers = {};
                if (Number.isFinite(error.retryAfterMs)) {
                    body.retryAfterMs = error.retryAfterMs;
                    headers['Retry-After'] = String(Math.ceil(error.retryAfterMs / 1000));
                }
                return send(res, error.status, body, headers);
            }
            console.error(error);
            send(res, 500, { error: 'Lỗi máy chủ.' });
        }
    });
    server.listen(PORT, '0.0.0.0', () => {
        console.log(`Lẩu Việt POS đang chạy: http://localhost:${PORT}`);
        console.log(`Điện thoại cùng Wi-Fi truy cập qua: ${lanOrigin()}`);
        console.log('Link QR từng bàn: đăng nhập admin > Quản lý thực đơn > "QR từng bàn".');
    });
}
