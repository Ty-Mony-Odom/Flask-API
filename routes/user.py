from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime, timedelta, timezone
import jwt
import os
from app import app, db
from models import *

def get_request_data():
    data = {}

    # JSON request (application/json)
    if request.is_json:
        data.update(request.get_json() or {})

    # Form-data & x-www-form-urlencoded
    if request.form:
        data.update(request.form.to_dict())

    # File upload support (multipart/form-data)
    if request.files:
        data['files'] = request.files

    return data

def parse_bool(value):
    if isinstance(value, bool):
        return value
    if str(value).lower() in ['true', '1', 't', 'y', 'yes']:
        return True
    if str(value).lower() in ['false', '0', 'f', 'n', 'no']:
        return False
    return False # Default fallback

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        try:
            if token.startswith('Bearer '):
                token = token[7:]
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.get(data['user_id'])
            if not current_user:
                return jsonify({'message': 'User not found'}), 401
        except:
            return jsonify({'message': 'Token is invalid'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(current_user, *args, **kwargs):
        if not current_user.is_admin:
            return jsonify({'message': 'Admin access required'}), 403
        return f(current_user, *args, **kwargs)
    return decorated

# Customer Routes
@app.route('/api/front/register', methods=['POST'])
def register():
    data = get_request_data()
    
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'message': 'Email already exists'}), 400
    
    hashed_password = generate_password_hash(data['password'])
    new_user = User(
        email=data['email'],
        password=hashed_password,
        name=data['name']
    )
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/api/front/login', methods=['POST'])
def login():
    data = get_request_data()
    user = User.query.filter_by(email=data['email']).first()
    
    if not user or not check_password_hash(user.password, data['password']):
        return jsonify({'message': 'Invalid credentials'}), 401
    
    token = jwt.encode({
        'user_id': user.id,
        'exp': datetime.now(timezone.utc) + timedelta(hours=24)
    }, app.config['SECRET_KEY'], algorithm="HS256")
    
    return jsonify({
        'token': token,
        'user': {
            'id': user.id,
            'email': user.email,
            'name': user.name,
            'is_admin': user.is_admin
        }
    })

@app.route('/api/front/reset-password', methods=['POST'])
@token_required
def reset_password(current_user):
    data = get_request_data()
    
    if not check_password_hash(current_user.password, data['old_password']):
        return jsonify({'message': 'Invalid old password'}), 400
    
    current_user.password = generate_password_hash(data['new_password'])
    db.session.commit()
    
    return jsonify({'message': 'Password updated successfully'})

@app.route('/api/front/logout', methods=['POST'])
@token_required
def logout(current_user):
    return jsonify({'message': 'Logged out successfully'})

@app.route('/api/front/categories', methods=['GET'])
def get_categories():
    categories = Category.query.all()
    return jsonify([{
        'id': c.id,
        'name': c.name,
        'description': c.description
    } for c in categories])

@app.route('/api/front/products', methods=['GET'])
def get_products():
    products = Product.query.all()
    return jsonify([{
        'id': p.id,
        'name': p.name,
        'description': p.description,
        'price': p.price,
        'stock': p.stock,
        'category_id': p.category_id,
        'category_name': p.category.name,
        'image_url': p.image_url
    } for p in products])

@app.route('/api/front/products/category/<int:category_id>', methods=['GET'])
def get_products_by_category(category_id):
    products = Product.query.filter_by(category_id=category_id).all()
    return jsonify([{
        'id': p.id,
        'name': p.name,
        'description': p.description,
        'price': p.price,
        'stock': p.stock,
        'category_id': p.category_id,
        'image_url': p.image_url
    } for p in products])

@app.route('/api/front/cart', methods=['GET'])
@token_required
def get_cart(current_user):
    cart_items = Cart.query.filter_by(user_id=current_user.id).all()
    total = sum(item.product.price * item.quantity for item in cart_items)
    
    return jsonify({
        'items': [{
            'id': item.id,
            'product_id': item.product_id,
            'product_name': item.product.name,
            'price': item.product.price,
            'quantity': item.quantity,
            'subtotal': item.product.price * item.quantity
        } for item in cart_items],
        'total': total
    })

@app.route('/api/front/cart', methods=['POST'])
@token_required
def add_to_cart(current_user):
    data = get_request_data()
    product = Product.query.get(data['product_id'])
    
    if not product:
        return jsonify({'message': 'Product not found'}), 404
    
    if product.stock < data.get('quantity', 1):
        return jsonify({'message': 'Insufficient stock'}), 400
    
    cart_item = Cart.query.filter_by(
        user_id=current_user.id,
        product_id=data['product_id']
    ).first()
    
    if cart_item:
        cart_item.quantity += data.get('quantity', 1)
    else:
        cart_item = Cart(
            user_id=current_user.id,
            product_id=data['product_id'],
            quantity=data.get('quantity', 1)
        )
        db.session.add(cart_item)
    
    db.session.commit()
    return jsonify({'message': 'Product added to cart'}), 201

@app.route('/api/front/cart/<int:item_id>', methods=['DELETE'])
@token_required
def remove_from_cart(current_user, item_id):
    cart_item = Cart.query.filter_by(id=item_id, user_id=current_user.id).first()
    
    if not cart_item:
        return jsonify({'message': 'Cart item not found'}), 404
    
    db.session.delete(cart_item)
    db.session.commit()
    return jsonify({'message': 'Item removed from cart'})

@app.route('/api/front/checkout', methods=['POST'])
@token_required
def checkout(current_user):
    cart_items = Cart.query.filter_by(user_id=current_user.id).all()
    
    if not cart_items:
        return jsonify({'message': 'Cart is empty'}), 400
    
    total = 0
    order = Order(user_id=current_user.id, total_amount=0)
    db.session.add(order)
    db.session.flush()
    
    for item in cart_items:
        if item.product.stock < item.quantity:
            db.session.rollback()
            return jsonify({'message': f'Insufficient stock for {item.product.name}'}), 400
        
        order_item = OrderItem(
            order_id=order.id,
            product_id=item.product_id,
            quantity=item.quantity,
            price=item.product.price
        )
        db.session.add(order_item)
        
        item.product.stock -= item.quantity
        total += item.product.price * item.quantity
        db.session.delete(item)
    
    order.total_amount = total
    db.session.commit()
    
    return jsonify({
        'message': 'Order placed successfully',
        'order_id': order.id,
        'total': total
    }), 201

@app.route('/api/front/orders', methods=['GET'])
@token_required
def get_orders(current_user):
    orders = Order.query.filter_by(user_id=current_user.id).all()
    return jsonify([{
        'id': o.id,
        'total_amount': o.total_amount,
        'status': o.status,
        'items': [{
            'product_name': item.product.name,
            'quantity': item.quantity,
            'price': item.price
        } for item in o.order_items]
    } for o in orders])

# Admin Routes
@app.route('/api/admin/users', methods=['GET'])
@token_required
@admin_required
def get_users(current_user):
    users = User.query.all()
    return jsonify([{
        'id': u.id,
        'email': u.email,
        'name': u.name,
        'is_admin': u.is_admin
    } for u in users])

@app.route('/api/admin/users', methods=['POST'])
@token_required
@admin_required
def create_user(current_user):
    data = get_request_data()
    
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'message': 'Email already exists'}), 400

    raw_is_admin = data.get('is_admin', False)

    is_admin_bool = str(raw_is_admin).lower() == 'true'

    new_user = User(
        email=data['email'],
        password=generate_password_hash(data['password']),
        name=data['name'],
        is_admin=is_admin_bool
    )
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({'message': 'User created successfully'}), 201


@app.route('/api/admin/users', methods=['PUT'])
@token_required
@admin_required
def update_user(current_user):
    data = get_request_data()
    
    # 1. Get the user_id from the request body instead of the URL
    user_id = data.get('id')
    
    if not user_id:
        return jsonify({'message': 'User ID is required in the request body'}), 400

    # 2. Find the user by the ID provided in the body
    user = User.query.get(user_id)
    if not user:
        return jsonify({'message': f'User with ID {user_id} not found'}), 404
    
    # 3. Update fields with Boolean check
    user.name = data.get('name', user.name)
    user.email = data.get('email', user.email)
    
    if 'is_admin' in data:
        user.is_admin = parse_bool(data.get('is_admin'))
    
    if 'password' in data and data['password']:
        user.password = generate_password_hash(data['password'])
    
    db.session.commit() #
    return jsonify({'message': 'User updated successfully'})

@app.route('/api/admin/users', methods=['DELETE']) # URL is now just /api/admin/users
@token_required
@admin_required
def delete_user(current_user):
    data = get_request_data()
    user_id = data.get('id') # Get ID from body
    
    if not user_id:
        return jsonify({'message': 'User ID is required in the request body'}), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404
    
    # Safety check: Prevent admin from deleting themselves
    if user.id == current_user.id:
        return jsonify({'message': 'You cannot delete your own account'}), 400
    
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'User deleted successfully'})

@app.route('/api/admin/categories', methods=['POST'])
@token_required
@admin_required
def create_category(current_user):
    data = get_request_data()
    category = Category(
        name=data['name'],
        description=data.get('description')
    )
    db.session.add(category)
    db.session.commit()
    return jsonify({'message': 'Category created successfully'}), 201

@app.route('/api/admin/categories/<int:category_id>', methods=['PUT'])
@token_required
@admin_required
def update_category(current_user, category_id):
    category = Category.query.get(category_id)
    if not category:
        return jsonify({'message': 'Category not found'}), 404
    
    data = get_request_data()
    category.name = data.get('name', category.name)
    category.description = data.get('description', category.description)
    
    db.session.commit()
    return jsonify({'message': 'Category updated successfully'})

@app.route('/api/admin/categories/<int:category_id>', methods=['DELETE'])
@token_required
@admin_required
def delete_category(current_user, category_id):
    category = Category.query.get(category_id)
    if not category:
        return jsonify({'message': 'Category not found'}), 404
    
    db.session.delete(category)
    db.session.commit()
    return jsonify({'message': 'Category deleted successfully'})

@app.route('/api/admin/products', methods=['POST'])
@token_required
@admin_required
def create_product(current_user):
    data = get_request_data()
    product = Product(
        name=data['name'],
        description=data.get('description'),
        price=data['price'],
        stock=data.get('stock', 0),
        category_id=data['category_id'],
        image_url=data.get('image_url')
    )
    db.session.add(product)
    db.session.commit()
    return jsonify({'message': 'Product created successfully'}), 201

@app.route('/api/admin/products', methods=['PUT']) # Removed <int:product_id>
@token_required
@admin_required
def update_product(current_user):
    data = get_request_data()
    product_id = data.get('id')
    
    if not product_id:
        return jsonify({'message': 'Product ID is required in the request body'}), 400

    product = Product.query.get(product_id)
    if not product:
        return jsonify({'message': 'Product not found'}), 404
    
    product.name = data.get('name', product.name)
    product.description = data.get('description', product.description)
    product.price = data.get('price', product.price)
    product.stock = data.get('stock', product.stock)
    product.category_id = data.get('category_id', product.category_id)
    product.image_url = data.get('image_url', product.image_url)
    
    db.session.commit()
    return jsonify({'message': 'Product updated successfully'})

@app.route('/api/admin/products', methods=['DELETE']) # Removed <int:product_id>
@token_required
@admin_required
def delete_product(current_user):
    data = get_request_data()
    product_id = data.get('id') # Extract ID from body
    
    if not product_id:
        return jsonify({'message': 'Product ID is required'}), 400

    product = Product.query.get(product_id)
    if not product:
        return jsonify({'message': 'Product not found'}), 404
    
    db.session.delete(product)
    db.session.commit()
    return jsonify({'message': 'Product deleted successfully'})

@app.route('/api/admin/orders/status', methods=['PUT']) # Changed path to be descriptive
@token_required
@admin_required
def update_order_status(current_user):
    data = get_request_data()
    order_id = data.get('id') # Extract ID from body
    
    if not order_id:
        return jsonify({'message': 'Order ID is required'}), 400

    order = Order.query.get(order_id)
    if not order:
        return jsonify({'message': 'Order not found'}), 404
    
    order.status = data.get('status', order.status)
    db.session.commit()
    return jsonify({'message': 'Order updated successfully'})

@app.route('/api/admin/orders/all', methods=['GET'])
@token_required
@admin_required
def get_all_orders(current_user):
    # Fetch all orders from the database
    orders = Order.query.all()
    
    if not orders:
        return jsonify({'message': 'No orders found', 'orders': []}), 200

    order_list = []
    for order in orders:
        # Get user info for the order
        user = User.query.get(order.user_id)
        
        order_data = {
            'order_id': order.id,
            'user_email': user.email if user else 'Unknown User',
            'total_amount': order.total_amount,
            'status': order.status,
            'items': [
                {
                    'product_id': item.product_id,
                    'product_name': item.product.name,
                    'quantity': item.quantity,
                    'price': item.price
                } for item in order.order_items
            ]
        }
        order_list.append(order_data)

    return jsonify(order_list), 200

@app.route('/api/admin/reports/sales', methods=['GET'])
@token_required
@admin_required
def get_sales_report(current_user):
    orders = Order.query.all()
    total_sales = sum(o.total_amount for o in orders)
    total_orders = len(orders)
    
    # Sales by status
    status_breakdown = {}
    for order in orders:
        status_breakdown[order.status] = status_breakdown.get(order.status, 0) + order.total_amount
    
    return jsonify({
        'total_sales': total_sales,
        'total_orders': total_orders,
        'average_order_value': total_sales / total_orders if total_orders > 0 else 0,
        'status_breakdown': status_breakdown
    })
