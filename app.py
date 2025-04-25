# 📦 중고거래 플랫폼 - Flask + MySQL + 전체 백엔드 코드

from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask import flash
import jwt
import datetime
import jwt.exceptions

app = Flask(__name__)
CORS(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://myuser:051122@localhost:3306/marketplace'
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# 데이터 모델
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    bio = db.Column(db.String(200))
    is_admin = db.Column(db.Boolean, default=False)
    nickname = db.Column(db.String(50))  # ✅ 새 필드 추가


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200))
    price = db.Column(db.Float, nullable=False)
    seller_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    seller = db.relationship('User', backref='products')  # 👈 관계 설정

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reporter_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'))
    reason = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    content = db.Column(db.String(500))
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)

    # 관계 설정 추가 👇
    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref='received_messages')

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    amount = db.Column(db.Float)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_transactions')
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref='received_transactions')

class Block(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    blocker_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    blocked_user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    blocked_product_id = db.Column(db.Integer, db.ForeignKey('product.id'))
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

@app.context_processor
def inject_config():
    return dict(config=app.config)

@app.context_processor
def inject_user_info():
    import jwt
    token = session.get('token')
    if token:
        try:
            user_info = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            return dict(user_info=user_info)
        except jwt.ExpiredSignatureError:
            return dict(user_info=None)
    return dict(user_info=None)

# 라우트 정의
@app.route('/')
def home():
    products = Product.query.all()
    user_id = None
    if 'token' in session:
        decoded = jwt.decode(session['token'], app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = decoded['user_id']
        blocked_users = db.session.query(Block.blocked_user_id).filter_by(blocker_id=user_id)
        blocked_products = db.session.query(Block.blocked_product_id).filter_by(blocker_id=user_id)

        products = Product.query.filter(
            ~Product.id.in_(blocked_products),
            ~Product.seller_id.in_(blocked_users)
        ).all()

    return render_template('index.html', products=products, user_id=user_id)


@app.route('/search')
def search():
    keyword = request.args.get('q', '')

    # 조건에 따라 상품 검색
    if keyword:
        results = Product.query.filter(Product.name.like(f"%{keyword}%")).all()
    else:
        results = Product.query.all()

    # 로그인된 사용자의 ID 추출
    user_id = None
    if 'token' in session:
        try:
            decoded = jwt.decode(session['token'], app.config['SECRET_KEY'], algorithms=['HS256'])
            user_id = decoded['user_id']
        except jwt.ExpiredSignatureError:
            session.pop('token', None)
            return redirect(url_for('login'))

    return render_template('index.html', products=results, keyword=keyword, user_id=user_id)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        nickname = request.form['nickname']
        new_user = User(username=username, password=password, nickname=nickname)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'token' in session:
        return redirect(url_for('home'))  # 이미 로그인한 상태면 홈으로

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            token = jwt.encode({'user_id': user.id, 'is_admin': user.is_admin, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)}, app.config['SECRET_KEY'])
            session['token'] = token
            return redirect(url_for('home'))
        return '로그인 실패'
    return render_template('login.html')

@app.route('/add', methods=['GET', 'POST'])
def add_product():
    token = session.get('token')
    if not token:
        return redirect(url_for('login'))
    try:
        decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        if request.method == 'POST':
            name = request.form['name']
            description = request.form['description']
            price = float(request.form['price'])
            new_product = Product(name=name, description=description, price=price, seller_id=decoded['user_id'])
            db.session.add(new_product)
            db.session.commit()
            return redirect(url_for('home'))
        return render_template('add.html')
    except:
        return '토큰 오류'

@app.route('/report', methods=['POST'])
def report():
    token = session.get('token')
    if not token:
        return redirect(url_for('login'))
    decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    product_id = request.form['product_id']
    reason = request.form['reason']
    report = Report(reporter_id=decoded['user_id'], product_id=product_id, reason=reason)
    db.session.add(report)
    db.session.commit()
    return redirect(url_for('home'))

@app.route('/admin/reports')
def view_reports():
    token = session.get('token')
    if not token:
        return redirect(url_for('login'))
    decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    if not decoded.get('is_admin'):
        return '접근 권한 없음'
    reports = Report.query.all()
    return render_template('reports.html', reports=reports)

@app.route('/admin/products/delete/<int:product_id>', methods=['POST'])
def delete_product(product_id):
    token = session.get('token')
    if not token:
        return redirect(url_for('login'))
    decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    if not decoded.get('is_admin'):
        return '권한 없음'
    product = Product.query.get(product_id)
    if product:
        db.session.delete(product)
        db.session.commit()
    return redirect(url_for('home'))

@app.route('/send_message', methods=['POST'])
def send_message():
    token = session.get('token')
    if not token:
        return redirect(url_for('login'))

    try:
        decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        sender_id = decoded['user_id']
        receiver_id = int(request.form['receiver_id'])
        content = request.form['content'].strip()

        # ✅ 자기 자신에게는 쪽지 보낼 수 없음
        if sender_id == receiver_id:
            return "자기 자신에게는 쪽지를 보낼 수 없습니다.", 400

        # ✅ 내용이 비어있는 경우
        if not content:
            return "쪽지 내용을 입력하세요.", 400

        # ✅ 상대방이 존재하는지 확인
        receiver = User.query.get(receiver_id)
        if not receiver:
            return "존재하지 않는 사용자입니다.", 404

        # ✅ 메시지 저장
        msg = Message(sender_id=sender_id, receiver_id=receiver_id, content=content)
        db.session.add(msg)
        db.session.commit()
        return redirect(url_for('chat', user_id=receiver_id))

    except Exception as e:
        return f"쪽지 전송 중 오류 발생: {e}", 500


@app.route('/messages')
def view_messages():
    token = session.get('token')
    if not token:
        return redirect(url_for('login'))
    decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    uid = decoded['user_id']
    inbox = Message.query.filter_by(receiver_id=uid).all()
    sent = Message.query.filter_by(sender_id=uid).all()

    for m in inbox:
        m.is_read = True
    db.session.commit()

    return render_template('messages.html', inbox=inbox, sent=sent)
def chat_rooms():
    token = session.get('token')
    if not token:
        return redirect(url_for('login'))

    decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    user_id = decoded['user_id']

    # 1. 쪽지를 주고받은 상대방 ID 모으기
    sent = db.session.query(Message.receiver_id).filter(Message.sender_id == user_id)
    received = db.session.query(Message.sender_id).filter(Message.receiver_id == user_id)
    user_ids = {uid for uid, in sent.union(received).all() if uid != user_id}

    # 2. 채팅방 구성
    chats = []
    for uid in user_ids:
        partner = User.query.get(uid)
        last_message = Message.query.filter(
            ((Message.sender_id == user_id) & (Message.receiver_id == uid)) |
            ((Message.sender_id == uid) & (Message.receiver_id == user_id))
        ).order_by(Message.timestamp.desc()).first()

        if last_message:
            chats.append({'partner': partner, 'last_message': last_message})

    return render_template('messages.html', chats=chats)

@app.route('/messages/delete/<int:message_id>', methods=['POST'])
def delete_message(message_id):
    token = session.get('token')
    if not token:
        return redirect(url_for('login'))
    decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    msg = Message.query.get(message_id)
    if msg and (msg.sender_id == decoded['user_id'] or msg.receiver_id == decoded['user_id']):
        db.session.delete(msg)
        db.session.commit()
    return redirect(url_for('view_messages'))

@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    token = session.get('token')
    if not token:
        return redirect(url_for('login'))

    decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    sender_id = decoded['user_id']

    if request.method == 'POST':
        try:
            receiver_id = int(request.form['receiver_id'])
            amount = float(request.form['amount'])

            if sender_id == receiver_id:
                return '❌ 자기 자신에게는 송금할 수 없습니다.'

            if amount <= 0:
                return '❌ 0보다 큰 금액을 입력해주세요.'

            # 💸 송금 내역 저장
            transaction = Transaction(sender_id=sender_id, receiver_id=receiver_id, amount=amount)
            db.session.add(transaction)

            # 💬 송금 메시지도 자동으로 전송
            msg_content = f"{amount}원을 송금했습니다."
            msg = Message(sender_id=sender_id, receiver_id=receiver_id, content=msg_content)
            db.session.add(msg)

            db.session.commit()
            return redirect(url_for('chat', user_id=receiver_id))

        except ValueError:
            return '❌ 금액은 숫자로 입력해주세요.'

        except Exception as e:
            return f'⚠️ 오류 발생: {e}'

    return render_template('transfer.html')

@app.route('/logout')
def logout():
    session.pop('token', None)
    return redirect(url_for('home'))
@app.route('/mypage', methods=['GET', 'POST'])
def mypage():
    token = session.get('token')
    if not token:
        return redirect(url_for('login'))

    try:
        decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user = User.query.get(decoded['user_id'])
        my_products = Product.query.filter_by(seller_id=user.id).all()
        my_transactions = Transaction.query.filter_by(sender_id=user.id).all()
        received_transactions = Transaction.query.filter_by(receiver_id=user.id).all()  # ✅ 받은 송금

        inbox = Message.query.filter_by(receiver_id=user.id).all()
        sent = Message.query.filter_by(sender_id=user.id).all()

        error_msg = None
        if request.method == 'POST':
            current_password = request.form.get('current_password')
            new_password = request.form.get('new_password')
            new_bio = request.form.get('bio')
            new_nickname = request.form.get('nickname')

            if current_password and not bcrypt.check_password_hash(user.password, current_password):
                error_msg = '❌ 현재 비밀번호가 올바르지 않습니다.'
            else:
                if new_password:
                    user.password = bcrypt.generate_password_hash(new_password).decode('utf-8')
                if new_bio:
                    user.bio = new_bio
                if new_nickname:
                    user.nickname = new_nickname
                db.session.commit()
                return redirect(url_for('mypage'))

        return render_template(
            'mypage.html',
            user=user,
            products=my_products,
            transactions=my_transactions,
            received_transactions=received_transactions,  # 👈 추가
            inbox=inbox,
            sent=sent,
            error=error_msg
        )

    except Exception as e:
        return f'오류 발생: {e}'

@app.route('/chat/<int:user_id>', methods=['GET', 'POST'])
def chat(user_id):
    token = session.get('token')
    if not token:
        return redirect(url_for('login'))

    try:
        decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        current_user_id = decoded['user_id']

        # 메시지 전송
        if request.method == 'POST':
            content = request.form['content']
            if content:
                msg = Message(
                    sender_id=current_user_id,
                    receiver_id=user_id,
                    content=content
                )
                db.session.add(msg)
                db.session.commit()
                return redirect(url_for('chat', user_id=user_id))

        # 대화 상대 정보
        partner = User.query.get(user_id)
        partner_nickname = partner.nickname or partner.username

        # 전체 메시지
        messages = Message.query.filter(
            ((Message.sender_id == current_user_id) & (Message.receiver_id == user_id)) |
            ((Message.sender_id == user_id) & (Message.receiver_id == current_user_id))
        ).order_by(Message.timestamp).all()

        # 읽음 처리
        for msg in messages:
            if msg.receiver_id == current_user_id and not msg.is_read:
                msg.is_read = True
        db.session.commit()

        return render_template(
            'chat.html',
            messages=messages,
            partner_nickname=partner_nickname,
            session_user_id=current_user_id,
            partner_id=user_id  # ✅ 이 부분 추가!
        )

    except Exception as e:
        return f'오류 발생: {e}'

@app.route('/chat/<int:user_id>/messages')
def chat_messages(user_id):
    token = session.get('token')
    if not token:
        return '', 401

    decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    current_user_id = decoded['user_id']

    messages = Message.query.filter(
        ((Message.sender_id == current_user_id) & (Message.receiver_id == user_id)) |
        ((Message.sender_id == user_id) & (Message.receiver_id == current_user_id))
    ).order_by(Message.timestamp).all()

    return render_template('_message_list.html', messages=messages, session_user_id=current_user_id)
@app.route('/message_read/<int:msg_id>', methods=['POST'])
def mark_message_read(msg_id):
    token = session.get('token')
    if not token:
        return '', 401

    decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    user_id = decoded['user_id']

    msg = Message.query.get(msg_id)
    if msg and msg.receiver_id == user_id and not msg.is_read:
        msg.is_read = True
        db.session.commit()

    return '', 204
@app.route('/chats')
def chat_rooms():
    token = session.get('token')
    if not token:
        return redirect(url_for('login'))

    decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    user_id = decoded['user_id']

    all_msgs = Message.query.filter(
        (Message.sender_id == user_id) | (Message.receiver_id == user_id)
    ).order_by(Message.timestamp.desc()).all()

    partners = {}  # {상대방 ID: 마지막 메시지}

    for msg in all_msgs:
        if msg.sender_id == user_id:
            partner_id = msg.receiver_id
        else:
            partner_id = msg.sender_id

        if partner_id and partner_id not in partners:
            partners[partner_id] = msg

    chat_list = []
    for pid, last_msg in partners.items():
        partner = User.query.filter_by(id=pid).first()
        if partner is None:
            print('⚠️ 상대방이 DB에 없음:', pid)
            continue

        chat_list.append({
            'partner': partner,
            'last_message': last_msg,
            'sent_by_me': last_msg.sender_id == user_id,
            'is_read': last_msg.is_read,
            'msg_id': last_msg.id,
        })

    return render_template('chat_rooms.html', chats=chat_list)

@app.route('/chat/delete/<int:partner_id>', methods=['POST'])
def delete_chat(partner_id):
    token = session.get('token')
    if not token:
        return redirect(url_for('login'))

    decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    user_id = decoded['user_id']

    # 양쪽 유저 간의 메시지를 모두 삭제
    Message.query.filter(
        ((Message.sender_id == user_id) & (Message.receiver_id == partner_id)) |
        ((Message.sender_id == partner_id) & (Message.receiver_id == user_id))
    ).delete()
    db.session.commit()
    return redirect(url_for('chat_rooms'))
@app.route('/edit_product/<int:product_id>', methods=['GET', 'POST'])
def edit_product(product_id):
    token = session.get('token')
    if not token:
        return redirect(url_for('login'))

    try:
        decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = decoded['user_id']
        product = Product.query.get(product_id)

        if not product or product.seller_id != user_id:
            return '수정 권한이 없습니다.', 403

        if request.method == 'POST':
            product.name = request.form['name']
            product.description = request.form['description']
            product.price = float(request.form['price'])
            db.session.commit()

            flash('✅ 상품 정보가 성공적으로 수정되었습니다!', 'success')
            return redirect(url_for('mypage'))

        return render_template('edit_product.html', product=product)

    except Exception as e:
        return f'오류 발생: {e}'

@app.route('/delete_product/<int:product_id>', methods=['POST'])
def delete_product_user(product_id):
    token = session.get('token')
    if not token:
        return redirect(url_for('login'))
    decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    user_id = decoded['user_id']

    product = Product.query.get_or_404(product_id)

    if product.seller_id != user_id:
        return '❌ 삭제 권한이 없습니다.', 403

    db.session.delete(product)
    db.session.commit()
    flash('✅ 상품이 삭제되었습니다.', 'success')
    return redirect(url_for('mypage'))

@app.route('/transfer/<int:user_id>', methods=['POST'])
def transfer_to_user(user_id):
    token = session.get('token')
    if not token:
        return redirect(url_for('login'))

    decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    sender_id = decoded['user_id']
    amount = float(request.form['amount'])

    if sender_id == user_id:
        return '❌ 자기 자신에게는 송금할 수 없습니다.'

    if amount <= 0:
        return '❌ 금액을 정확히 입력해주세요.'

    tx = Transaction(sender_id=sender_id, receiver_id=user_id, amount=amount)
    db.session.add(tx)
    db.session.commit()

    return redirect(url_for('chat', user_id=user_id))

@app.route('/block_user/<int:user_id>', methods=['POST'])
def block_user(user_id):
    token = session.get('token')
    if not token:
        return redirect(url_for('login'))

    decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    blocker_id = decoded['user_id']

    existing = Block.query.filter_by(blocker_id=blocker_id, blocked_user_id=user_id).first()
    if not existing:
        block = Block(blocker_id=blocker_id, blocked_user_id=user_id)
        db.session.add(block)
        db.session.commit()
    return redirect(url_for('home'))

@app.route('/block_product/<int:product_id>', methods=['POST'])
def block_product(product_id):
    token = session.get('token')
    if not token:
        return redirect(url_for('login'))

    decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    blocker_id = decoded['user_id']

    existing = Block.query.filter_by(blocker_id=blocker_id, blocked_product_id=product_id).first()
    if not existing:
        block = Block(blocker_id=blocker_id, blocked_product_id=product_id)
        db.session.add(block)
        db.session.commit()
    return redirect(url_for('home'))

@app.route('/blocked')
def blocked_items():
    token = session.get('token')
    if not token:
        return redirect(url_for('login'))
    decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    uid = decoded['user_id']

    blocks = Block.query.filter_by(blocker_id=uid).all()
    return render_template('blocked.html', blocks=blocks)

@app.route('/some_route')
def some_view():
    token = session.get('token')
    if not token:
        return redirect(url_for('login'))

    try:
        decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        session.pop('token', None)  # 세션에서 토큰 삭제
        return redirect(url_for('login'))  # 로그인 페이지로 이동
@app.before_request
def check_token_expiry():
    token = session.get('token')
    if token:
        try:
            jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            session.pop('token', None)
            flash("세션이 만료되었습니다. 다시 로그인해주세요.", "warning")
            return redirect(url_for('login'))

@app.route('/transfer_in_chat', methods=['POST'])
def transfer_in_chat():
    token = session.get('token')
    if not token:
        return redirect(url_for('login'))

    decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    sender_id = decoded['user_id']

    try:
        receiver_id = int(request.form['receiver_id'])
        amount = float(request.form['amount'])

        if receiver_id == sender_id:
            flash('❌ 자기 자신에게는 송금할 수 없습니다.', 'danger')
        elif amount <= 0:
            flash('❌ 유효한 금액을 입력해주세요.', 'danger')
        else:
            tx = Transaction(sender_id=sender_id, receiver_id=receiver_id, amount=amount)
            db.session.add(tx)
            db.session.commit()
            flash('✅ 송금이 완료되었습니다!', 'success')

    except Exception as e:
        flash(f'오류 발생: {e}', 'danger')

    return redirect(url_for('chat', user_id=receiver_id))

# 앱 실행
if __name__ == '__main__':
    with app.app_context():
        try:
            db.create_all()
            print("✅ 데이터베이스 테이블이 준비되었습니다.")
        except Exception as e:
            print(f"⚠️ DB 생성 오류: {e}")

    app.run(debug=True)
