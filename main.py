"""
Békovv Backend - ENHANCED VERSION
All requested features implemented:
1. Multi-language support (EN/RU/UZ)
2. Fixed receipt/avatar uploads with proper URL handling
3. Product image upload (not URL)
4. Proper validation messages
5. Enhanced features for admin and user
"""

from fastapi import FastAPI, HTTPException, Request, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional, List
import sqlite3
from datetime import datetime, timedelta
import json
import base64
import os
import hashlib
import secrets
import shutil

app = FastAPI(title="Békovv API Enhanced", version="6.0.0")

# Create upload directories
for folder in ["uploads/receipts", "uploads/avatars", "uploads/products"]:
    os.makedirs(folder, exist_ok=True)

# Mount uploads with proper static file serving
app.mount("/uploads", StaticFiles(directory="uploads"), name="uploads")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============ DATABASE ============
class Database:
    def __init__(self, db_path='bekovv_v6.db'):
        self.db_path = db_path
        self.init_db()
    
    def get_conn(self):
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn
    
    def init_db(self):
        conn = self.get_conn()
        c = conn.cursor()
        
        # Admin users
        c.execute('''CREATE TABLE IF NOT EXISTS admin_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            language TEXT DEFAULT 'en',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        
        # Default admin
        c.execute('SELECT * FROM admin_users WHERE username = ?', ('admin',))
        if not c.fetchone():
            c.execute('INSERT INTO admin_users (username, password_hash) VALUES (?, ?)', 
                     ('admin', hashlib.sha256('admin123'.encode()).hexdigest()))
        
        # Users
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            telegram_id TEXT PRIMARY KEY,
            name TEXT,
            email TEXT,
            phone TEXT,
            address TEXT,
            latitude REAL,
            longitude REAL,
            avatar TEXT,
            language TEXT DEFAULT 'en',
            profile_completed BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        
        # Products with local image support
        c.execute('''CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            name_ru TEXT,
            name_uz TEXT,
            description TEXT,
            description_ru TEXT,
            description_uz TEXT,
            price REAL NOT NULL,
            discount_price REAL,
            category TEXT,
            category_ru TEXT,
            category_uz TEXT,
            brand TEXT,
            image TEXT,
            stock INTEGER DEFAULT 0,
            is_active BOOLEAN DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        
        # Orders
        c.execute('''CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            order_number TEXT UNIQUE,
            telegram_id TEXT,
            items TEXT,
            total_amount REAL,
            shipping_address TEXT,
            latitude REAL,
            longitude REAL,
            status TEXT DEFAULT 'pending',
            payment_receipt TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        
        # Messages
        c.execute('''CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            telegram_id TEXT,
            message TEXT,
            is_from_admin BOOLEAN DEFAULT 0,
            is_read BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        
        # Wishlist
        c.execute('''CREATE TABLE IF NOT EXISTS wishlist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            telegram_id TEXT,
            product_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(telegram_id, product_id)
        )''')
        
        # Settings
        c.execute('''CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )''')
        
        # Default settings
        for key, val in [('payment_card_number', '8600 1234 5678 9012'),
                        ('payment_card_owner', 'Békovv Store'),
                        ('payment_bank_name', 'Uzcard')]:
            c.execute('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)', (key, val))
        
        # Admin sessions
        c.execute('''CREATE TABLE IF NOT EXISTS admin_sessions (
            token TEXT PRIMARY KEY,
            username TEXT,
            expires_at TIMESTAMP
        )''')
        
        # Sample products if empty
        c.execute('SELECT COUNT(*) FROM products')
        if c.fetchone()[0] == 0:
            products = [
                ('iPhone 15 Pro', 'iPhone 15 Pro', 'iPhone 15 Pro', 'Latest Apple flagship', 
                 'Флагман Apple', 'Apple flagmani', 1199.99, 1099.99, 'Phones', 'Телефоны', 
                 'Telefonlar', 'Apple', 'https://images.unsplash.com/photo-1695048133142-1a20484d2569?w=400', 50),
                ('Samsung S24', 'Samsung S24', 'Samsung S24', 'AI Powered Phone',
                 'Телефон с ИИ', 'AI telefon', 999.99, None, 'Phones', 'Телефоны',
                 'Telefonlar', 'Samsung', 'https://images.unsplash.com/photo-1610945415295-d9bbf067e59c?w=400', 30),
                ('MacBook Pro', 'MacBook Pro', 'MacBook Pro', 'Professional laptop',
                 'Профессиональный ноутбук', 'Professional noutbuk', 2499.99, 2299.99, 'Laptops', 
                 'Ноутбуки', 'Noutbuklar', 'Apple', 'https://images.unsplash.com/photo-1517336714731-489689fd1ca8?w=400', 20),
                ('AirPods Pro', 'AirPods Pro', 'AirPods Pro', 'Wireless earbuds',
                 'Беспроводные наушники', 'Simsiz quloqchinlar', 249.99, 229.99, 'Accessories',
                 'Аксессуары', 'Aksessuarlar', 'Apple', 'https://images.unsplash.com/photo-1600294037681-c80b4cb5b434?w=400', 100),
            ]
            c.executemany('''INSERT INTO products (name, name_ru, name_uz, description, 
                description_ru, description_uz, price, discount_price, category, category_ru,
                category_uz, brand, image, stock) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)''', products)
        
        conn.commit()
        conn.close()

db = Database()

# ============ HELPERS ============
def hash_pwd(pwd): return hashlib.sha256(pwd.encode()).hexdigest()

def verify_admin(token):
    if not token: return False
    conn = db.get_conn()
    c = conn.cursor()
    c.execute('SELECT * FROM admin_sessions WHERE token = ? AND expires_at > ?', 
              (token, datetime.now()))
    valid = c.fetchone() is not None
    conn.close()
    return valid

def get_base_url(request: Request):
    return str(request.base_url).rstrip('/')

def save_base64_image(base64_data: str, folder: str, prefix: str) -> str:
    """Save base64 image and return relative path"""
    if ',' in base64_data:
        base64_data = base64_data.split(',')[1]
    
    image_data = base64.b64decode(base64_data)
    filename = f"{prefix}_{int(datetime.now().timestamp())}_{secrets.token_hex(4)}.jpg"
    filepath = os.path.join(f"uploads/{folder}", filename)
    
    with open(filepath, "wb") as f:
        f.write(image_data)
    
    return f"/uploads/{folder}/{filename}"

# ============ MODELS ============
class AdminLogin(BaseModel):
    username: str
    password: str

class User(BaseModel):
    telegram_id: str
    name: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    address: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    language: Optional[str] = 'en'

class OrderCreate(BaseModel):
    telegram_id: str
    items: List[dict]
    total_amount: float
    shipping_address: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None

class ProductCreate(BaseModel):
    name: str
    name_ru: Optional[str] = None
    name_uz: Optional[str] = None
    description: Optional[str] = None
    description_ru: Optional[str] = None
    description_uz: Optional[str] = None
    price: float
    discount_price: Optional[float] = None
    category: Optional[str] = None
    category_ru: Optional[str] = None
    category_uz: Optional[str] = None
    brand: Optional[str] = None
    image: Optional[str] = None
    stock: int = 0

# ============ ADMIN AUTH ============
@app.post("/api/admin/login")
async def admin_login(creds: AdminLogin):
    conn = db.get_conn()
    c = conn.cursor()
    c.execute('SELECT * FROM admin_users WHERE username = ?', (creds.username,))
    admin = c.fetchone()
    
    if not admin or admin['password_hash'] != hash_pwd(creds.password):
        conn.close()
        raise HTTPException(401, "Invalid credentials")
    
    token = secrets.token_urlsafe(32)
    expires = datetime.now() + timedelta(hours=24)
    c.execute('INSERT INTO admin_sessions (token, username, expires_at) VALUES (?, ?, ?)',
              (token, creds.username, expires))
    conn.commit()
    conn.close()
    return {"token": token, "username": creds.username}

@app.get("/api/admin/verify")
async def verify_admin_token(request: Request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if verify_admin(token):
        return {"valid": True}
    raise HTTPException(401, "Invalid session")

@app.post("/api/admin/change-password")
async def change_password(data: dict, request: Request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not verify_admin(token):
        raise HTTPException(401, "Unauthorized")
    
    conn = db.get_conn()
    c = conn.cursor()
    c.execute('SELECT username FROM admin_sessions WHERE token = ?', (token,))
    session = c.fetchone()
    if not session:
        conn.close()
        raise HTTPException(401, "Invalid session")
    
    c.execute('SELECT password_hash FROM admin_users WHERE username = ?', (session['username'],))
    admin = c.fetchone()
    
    if admin['password_hash'] != hash_pwd(data.get('old_password', '')):
        conn.close()
        raise HTTPException(400, "Invalid current password")
    
    c.execute('UPDATE admin_users SET password_hash = ? WHERE username = ?',
              (hash_pwd(data['new_password']), session['username']))
    conn.commit()
    conn.close()
    return {"message": "Password changed"}

# ============ PRODUCTS ============
@app.get("/api/products")
async def get_products(lang: str = 'en'):
    conn = db.get_conn()
    c = conn.cursor()
    c.execute('SELECT * FROM products WHERE is_active = 1 ORDER BY created_at DESC')
    products = [dict(row) for row in c.fetchall()]
    conn.close()
    return products

@app.get("/api/products/{product_id}")
async def get_product(product_id: int):
    conn = db.get_conn()
    c = conn.cursor()
    c.execute('SELECT * FROM products WHERE id = ?', (product_id,))
    product = c.fetchone()
    conn.close()
    if not product:
        raise HTTPException(404, "Product not found")
    return dict(product)

@app.post("/api/products")
async def create_product(product: ProductCreate, request: Request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not verify_admin(token):
        raise HTTPException(401, "Unauthorized")
    
    conn = db.get_conn()
    c = conn.cursor()
    c.execute('''INSERT INTO products (name, name_ru, name_uz, description, description_ru,
        description_uz, price, discount_price, category, category_ru, category_uz, brand, image, stock)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
        (product.name, product.name_ru, product.name_uz, product.description, product.description_ru,
         product.description_uz, product.price, product.discount_price, product.category,
         product.category_ru, product.category_uz, product.brand, product.image, product.stock))
    product_id = c.lastrowid
    conn.commit()
    conn.close()
    return {"id": product_id, "message": "Product created"}

@app.post("/api/products/{product_id}/upload-image")
async def upload_product_image(product_id: int, data: dict, request: Request):
    """Upload product image as base64"""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not verify_admin(token):
        raise HTTPException(401, "Unauthorized")
    
    image_path = save_base64_image(data['image'], 'products', f'product_{product_id}')
    
    conn = db.get_conn()
    c = conn.cursor()
    c.execute('UPDATE products SET image = ? WHERE id = ?', (image_path, product_id))
    conn.commit()
    conn.close()
    
    return {"image_url": image_path}

@app.put("/api/products/{product_id}")
async def update_product(product_id: int, product: ProductCreate, request: Request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not verify_admin(token):
        raise HTTPException(401, "Unauthorized")
    
    conn = db.get_conn()
    c = conn.cursor()
    c.execute('''UPDATE products SET name=?, name_ru=?, name_uz=?, description=?, description_ru=?,
        description_uz=?, price=?, discount_price=?, category=?, category_ru=?, category_uz=?, 
        brand=?, image=?, stock=? WHERE id=?''',
        (product.name, product.name_ru, product.name_uz, product.description, product.description_ru,
         product.description_uz, product.price, product.discount_price, product.category,
         product.category_ru, product.category_uz, product.brand, product.image, product.stock, product_id))
    conn.commit()
    conn.close()
    return {"message": "Product updated"}

@app.delete("/api/products/{product_id}")
async def delete_product(product_id: int, request: Request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not verify_admin(token):
        raise HTTPException(401, "Unauthorized")
    
    conn = db.get_conn()
    c = conn.cursor()
    c.execute('UPDATE products SET is_active = 0 WHERE id = ?', (product_id,))
    conn.commit()
    conn.close()
    return {"message": "Product deleted"}

# ============ USERS ============
@app.get("/api/user/{telegram_id}")
async def get_user(telegram_id: str):
    conn = db.get_conn()
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE telegram_id = ?', (telegram_id,))
    user = c.fetchone()
    conn.close()
    return dict(user) if user else {"telegram_id": telegram_id, "profile_completed": False}

@app.post("/api/user/{telegram_id}")
async def update_user(telegram_id: str, user: User):
    profile_completed = bool(user.name and user.phone and user.address)
    
    conn = db.get_conn()
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE telegram_id = ?', (telegram_id,))
    existing = c.fetchone()
    
    if existing:
        c.execute('''UPDATE users SET name=?, email=?, phone=?, address=?, latitude=?, 
            longitude=?, language=?, profile_completed=? WHERE telegram_id=?''',
            (user.name, user.email, user.phone, user.address, user.latitude,
             user.longitude, user.language, profile_completed, telegram_id))
    else:
        c.execute('''INSERT INTO users (telegram_id, name, email, phone, address, latitude,
            longitude, language, profile_completed) VALUES (?,?,?,?,?,?,?,?,?)''',
            (telegram_id, user.name, user.email, user.phone, user.address,
             user.latitude, user.longitude, user.language, profile_completed))
    
    conn.commit()
    conn.close()
    return {"message": "Updated", "profile_completed": profile_completed}

@app.get("/api/user/{telegram_id}/check-profile")
async def check_profile(telegram_id: str):
    conn = db.get_conn()
    c = conn.cursor()
    c.execute('SELECT name, phone, address, latitude, longitude FROM users WHERE telegram_id = ?', (telegram_id,))
    user = c.fetchone()
    conn.close()
    
    if not user:
        return {"completed": False, "missing": ["name", "phone", "address", "location"]}
    
    missing = []
    if not user['name']: missing.append("name")
    if not user['phone']: missing.append("phone")
    if not user['address']: missing.append("address")
    if not user['latitude']: missing.append("location")
    
    return {"completed": len(missing) == 0, "missing": missing}

@app.post("/api/user/{telegram_id}/avatar")
async def upload_avatar(telegram_id: str, data: dict):
    avatar_path = save_base64_image(data['image'], 'avatars', f'avatar_{telegram_id}')
    
    conn = db.get_conn()
    c = conn.cursor()
    c.execute('UPDATE users SET avatar = ? WHERE telegram_id = ?', (avatar_path, telegram_id))
    conn.commit()
    conn.close()
    
    return {"avatar_url": avatar_path}

@app.get("/api/users")
async def get_all_users(request: Request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not verify_admin(token):
        raise HTTPException(401, "Unauthorized")
    
    conn = db.get_conn()
    c = conn.cursor()
    c.execute('''SELECT u.*, COUNT(o.id) as order_count, 
        COALESCE(SUM(o.total_amount), 0) as total_spent
        FROM users u LEFT JOIN orders o ON u.telegram_id = o.telegram_id
        GROUP BY u.telegram_id ORDER BY u.created_at DESC''')
    users = [dict(row) for row in c.fetchall()]
    conn.close()
    return users

# ============ ORDERS ============
@app.post("/api/orders")
async def create_order(order: OrderCreate):
    conn = db.get_conn()
    c = conn.cursor()
    
    # Check profile
    c.execute('SELECT name, phone, address FROM users WHERE telegram_id = ?', (order.telegram_id,))
    user = c.fetchone()
    if not user or not user['name'] or not user['phone'] or not user['address']:
        conn.close()
        raise HTTPException(400, "Please complete your profile first")
    
    order_number = f"BKV{int(datetime.now().timestamp())}{secrets.token_hex(2).upper()}"
    
    c.execute('''INSERT INTO orders (order_number, telegram_id, items, total_amount, 
        shipping_address, latitude, longitude, status, created_at) VALUES (?,?,?,?,?,?,?,?,?)''',
        (order_number, order.telegram_id, json.dumps(order.items), order.total_amount,
         order.shipping_address or user['address'], order.latitude, order.longitude, 
         'pending', datetime.now()))
    
    order_id = c.lastrowid
    
    # Update stock
    for item in order.items:
        c.execute('UPDATE products SET stock = stock - ? WHERE id = ?', (item['qty'], item['id']))
    
    conn.commit()
    conn.close()
    return {"order_id": order_id, "order_number": order_number}

@app.get("/api/orders")
async def get_all_orders(request: Request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not verify_admin(token):
        raise HTTPException(401, "Unauthorized")
    
    conn = db.get_conn()
    c = conn.cursor()
    c.execute('''SELECT o.*, u.name, u.phone, u.email, u.avatar
        FROM orders o LEFT JOIN users u ON o.telegram_id = u.telegram_id
        ORDER BY o.created_at DESC''')
    orders = [dict(row) for row in c.fetchall()]
    conn.close()
    
    for order in orders:
        order['items'] = json.loads(order['items'])
    return orders

@app.get("/api/orders/{telegram_id}")
async def get_user_orders(telegram_id: str):
    conn = db.get_conn()
    c = conn.cursor()
    c.execute('SELECT * FROM orders WHERE telegram_id = ? ORDER BY created_at DESC', (telegram_id,))
    orders = [dict(row) for row in c.fetchall()]
    conn.close()
    
    for order in orders:
        order['items'] = json.loads(order['items'])
    return orders

@app.put("/api/orders/{order_id}/status")
async def update_order_status(order_id: int, data: dict, request: Request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not verify_admin(token):
        raise HTTPException(401, "Unauthorized")
    
    conn = db.get_conn()
    c = conn.cursor()
    c.execute('UPDATE orders SET status = ? WHERE id = ?', (data['status'], order_id))
    conn.commit()
    conn.close()
    return {"message": "Status updated"}

@app.post("/api/orders/{order_id}/receipt-base64")
async def upload_receipt(order_id: int, data: dict):
    receipt_path = save_base64_image(data['image'], 'receipts', f'receipt_{order_id}')
    
    conn = db.get_conn()
    c = conn.cursor()
    c.execute('UPDATE orders SET payment_receipt = ? WHERE id = ?', (receipt_path, order_id))
    conn.commit()
    conn.close()
    
    return {"url": receipt_path}

# ============ MESSAGES ============
@app.post("/api/messages")
async def send_message(data: dict):
    conn = db.get_conn()
    c = conn.cursor()
    c.execute('INSERT INTO messages (telegram_id, message, is_from_admin) VALUES (?,?,?)',
              (data['telegram_id'], data['message'], data.get('is_from_admin', False)))
    conn.commit()
    conn.close()
    return {"message": "Sent"}

@app.get("/api/messages/{telegram_id}")
async def get_messages(telegram_id: str):
    conn = db.get_conn()
    c = conn.cursor()
    c.execute('SELECT * FROM messages WHERE telegram_id = ? ORDER BY created_at ASC', (telegram_id,))
    messages = [dict(row) for row in c.fetchall()]
    c.execute('UPDATE messages SET is_read = 1 WHERE telegram_id = ? AND is_from_admin = 1', (telegram_id,))
    conn.commit()
    conn.close()
    return messages

@app.get("/api/admin/messages")
async def get_conversations(request: Request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not verify_admin(token):
        raise HTTPException(401, "Unauthorized")
    
    conn = db.get_conn()
    c = conn.cursor()
    c.execute('''SELECT m.telegram_id, u.name, u.avatar,
        COUNT(CASE WHEN m.is_read = 0 AND m.is_from_admin = 0 THEN 1 END) as unread_count,
        MAX(m.created_at) as last_message_time
        FROM messages m LEFT JOIN users u ON m.telegram_id = u.telegram_id
        GROUP BY m.telegram_id ORDER BY last_message_time DESC''')
    convs = [dict(row) for row in c.fetchall()]
    conn.close()
    return convs

@app.post("/api/admin/messages/{telegram_id}")
async def admin_send_message(telegram_id: str, data: dict, request: Request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not verify_admin(token):
        raise HTTPException(401, "Unauthorized")
    
    conn = db.get_conn()
    c = conn.cursor()
    c.execute('INSERT INTO messages (telegram_id, message, is_from_admin) VALUES (?,?,1)',
              (telegram_id, data['message']))
    conn.commit()
    conn.close()
    return {"message": "Sent"}

# ============ WISHLIST ============
@app.get("/api/wishlist/{telegram_id}")
async def get_wishlist(telegram_id: str):
    conn = db.get_conn()
    c = conn.cursor()
    c.execute('''SELECT p.* FROM wishlist w JOIN products p ON w.product_id = p.id
        WHERE w.telegram_id = ? AND p.is_active = 1''', (telegram_id,))
    items = [dict(row) for row in c.fetchall()]
    conn.close()
    return items

@app.post("/api/wishlist/{telegram_id}/{product_id}")
async def toggle_wishlist(telegram_id: str, product_id: int):
    conn = db.get_conn()
    c = conn.cursor()
    c.execute('SELECT * FROM wishlist WHERE telegram_id = ? AND product_id = ?', (telegram_id, product_id))
    exists = c.fetchone()
    
    if exists:
        c.execute('DELETE FROM wishlist WHERE telegram_id = ? AND product_id = ?', (telegram_id, product_id))
        action = "removed"
    else:
        c.execute('INSERT INTO wishlist (telegram_id, product_id) VALUES (?,?)', (telegram_id, product_id))
        action = "added"
    
    conn.commit()
    conn.close()
    return {"action": action}

# ============ SETTINGS & STATS ============
@app.get("/api/settings/payment")
async def get_payment_settings():
    conn = db.get_conn()
    c = conn.cursor()
    settings = {}
    for key in ['payment_card_number', 'payment_card_owner', 'payment_bank_name']:
        c.execute('SELECT value FROM settings WHERE key = ?', (key,))
        r = c.fetchone()
        settings[key] = r['value'] if r else ''
    conn.close()
    return settings

@app.post("/api/settings/payment")
async def update_payment_settings(data: dict, request: Request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not verify_admin(token):
        raise HTTPException(401, "Unauthorized")
    
    conn = db.get_conn()
    c = conn.cursor()
    for key in ['payment_card_number', 'payment_card_owner', 'payment_bank_name']:
        if key in data:
            c.execute('UPDATE settings SET value = ? WHERE key = ?', (data[key], key))
    conn.commit()
    conn.close()
    return {"message": "Updated"}

@app.get("/api/stats")
async def get_stats():
    conn = db.get_conn()
    c = conn.cursor()
    
    c.execute('SELECT COUNT(*) FROM users')
    users = c.fetchone()[0]
    c.execute('SELECT COUNT(*) FROM orders')
    orders = c.fetchone()[0]
    c.execute('SELECT COALESCE(SUM(total_amount), 0) FROM orders WHERE status != "cancelled"')
    revenue = c.fetchone()[0]
    c.execute('SELECT COUNT(*) FROM products WHERE is_active = 1')
    products = c.fetchone()[0]
    
    conn.close()
    return {"users": users, "orders": orders, "revenue": float(revenue), "products": products}

@app.get("/api/admin/analytics/revenue")
async def get_revenue_analytics(days: int = 30, request: Request = None):
    conn = db.get_conn()
    c = conn.cursor()
    c.execute('''SELECT DATE(created_at) as date, COUNT(*) as order_count, 
        SUM(total_amount) as revenue FROM orders 
        WHERE status != 'cancelled' AND created_at >= date('now', '-' || ? || ' days')
        GROUP BY DATE(created_at) ORDER BY date ASC''', (days,))
    data = [dict(row) for row in c.fetchall()]
    conn.close()
    return data

@app.post("/api/admin/create")
async def create_admin(data: dict, request: Request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not verify_admin(token):
        raise HTTPException(401, "Unauthorized")
    
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    if not username or len(password) < 6:
        raise HTTPException(400, "Username required, password min 6 chars")
    
    conn = db.get_conn()
    c = conn.cursor()
    c.execute('SELECT * FROM admin_users WHERE username = ?', (username,))
    if c.fetchone():
        conn.close()
        raise HTTPException(400, "Username exists")
    
    c.execute('INSERT INTO admin_users (username, password_hash) VALUES (?,?)',
              (username, hash_pwd(password)))
    conn.commit()
    conn.close()
    return {"message": "Admin created"}

@app.get("/")
async def root():
    return {"name": "Békovv API Enhanced", "version": "6.0.0", "status": "running"}

@app.get("/health")
async def health():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    print("=" * 60)
    print("🚀 Békovv Backend v6.0 - Enhanced")
    print("=" * 60)
    print("📦 Database: bekovv_v6.db")
    print("🌐 Server: http://localhost:8000")
    print("📚 API Docs: http://localhost:8000/docs")
    print("=" * 60)
    print("🔐 Default Admin: admin / admin123")
    print("=" * 60)
    uvicorn.run(app, host="0.0.0.0", port=8000)