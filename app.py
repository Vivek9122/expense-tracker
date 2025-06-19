from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
from flask_mail import Mail, Message

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(24))
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///expenses.db')

# Email configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('EMAIL_USER')
app.config['MAIL_PASSWORD'] = os.environ.get('EMAIL_PASSWORD')

# Handle SQLite database URL for production
if app.config['SQLALCHEMY_DATABASE_URI'].startswith('postgres://'):
    app.config['SQLALCHEMY_DATABASE_URI'] = app.config['SQLALCHEMY_DATABASE_URI'].replace('postgres://', 'postgresql://', 1)

db = SQLAlchemy(app)
mail = Mail(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(512))
    expenses = db.relationship('Expense', backref='user', lazy=True)
    shared_expenses = db.relationship('ExpenseShare', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Expense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    shared_with = db.relationship('ExpenseShare', backref='expense', lazy=True)

class ExpenseShare(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    expense_id = db.Column(db.Integer, db.ForeignKey('expense.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, paid, rejected

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash('Username already exists!', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('Email already registered!', 'danger')
            return redirect(url_for('register'))

        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))
        
        flash('Invalid email or password!', 'danger')
        return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Get expenses created by current user
    expenses = Expense.query.filter_by(user_id=current_user.id).order_by(Expense.date.desc()).all()
    
    # Get expenses shared with current user (where you owe money)
    shared_expenses_owed = ExpenseShare.query.filter_by(user_id=current_user.id).all()
    
    # Get expenses that current user has shared with others (where others owe you)
    expenses_you_shared = db.session.query(ExpenseShare).join(Expense).filter(
        Expense.user_id == current_user.id
    ).all()
    
    # Calculate totals
    total_expenses = sum(expense.amount for expense in expenses)
    
    # Total amount you owe to others
    total_owed_by_you = sum(share.amount for share in shared_expenses_owed)
    
    # Total amount others owe you
    total_owed_to_you = sum(share.amount for share in expenses_you_shared)
    
    # Net shared expenses (what you owe minus what others owe you)
    total_shared = total_owed_by_you - total_owed_to_you
    
    # Pending payments (only what you owe to others with pending status)
    total_pending = sum(share.amount for share in shared_expenses_owed if share.status == 'pending')
    
    return render_template('dashboard.html',
                         expenses=expenses,
                         shared_expenses=shared_expenses_owed,
                         expenses_you_shared=expenses_you_shared,
                         total_expenses=total_expenses,
                         total_shared=abs(total_shared),  # Show absolute value
                         total_pending=total_pending,
                         total_owed_by_you=total_owed_by_you,
                         total_owed_to_you=total_owed_to_you)

@app.route('/add_expense', methods=['GET', 'POST'])
@login_required
def add_expense():
    if request.method == 'POST':
        amount = float(request.form['amount'])
        description = request.form['description']
        category = request.form['category']
        
        # Check if expense should be shared
        share_expense = request.form.get('share_expense')
        share_with_email = request.form.get('share_with')
        share_amount = request.form.get('share_amount')
        
        # Create the expense
        expense = Expense(
            amount=amount,
            description=description,
            category=category,
            user_id=current_user.id
        )
        db.session.add(expense)
        db.session.flush()  # Get the expense ID
        
        # Handle sharing if requested
        if share_expense and share_with_email and share_amount:
            try:
                share_amount_float = float(share_amount)
                
                # Find the user to share with
                shared_user = User.query.filter_by(email=share_with_email.strip()).first()
                
                if shared_user:
                    if shared_user.id != current_user.id:  # Can't share with yourself
                        if share_amount_float <= amount:  # Share amount can't exceed total
                            # Create the expense share
                            expense_share = ExpenseShare(
                                expense_id=expense.id,
                                user_id=shared_user.id,
                                amount=share_amount_float
                            )
                            db.session.add(expense_share)
                            
                            # Send email notification if configured
                            try:
                                if app.config['MAIL_USERNAME']:
                                    msg = Message(
                                        'New Expense Shared with You',
                                        sender=app.config['MAIL_USERNAME'],
                                        recipients=[share_with_email]
                                    )
                                    msg.body = f'''Hello,

{current_user.username} has shared an expense with you:
Description: {description}
Total Amount: ${amount}
Your Share: ${share_amount_float}
Category: {category}

Please log in to your account to view and manage this shared expense.

Best regards,
Expense Tracker Team'''
                                    mail.send(msg)
                            except Exception as e:
                                print(f"Failed to send email: {e}")
                            
                            flash(f'Expense added and shared with {share_with_email}!', 'success')
                        else:
                            flash('Share amount cannot exceed total expense amount!', 'warning')
                    else:
                        flash('You cannot share an expense with yourself!', 'warning')
                else:
                    flash(f'User with email {share_with_email} not found. Expense added but not shared.', 'warning')
            except ValueError:
                flash('Invalid share amount. Expense added but not shared.', 'warning')
        else:
            flash('Expense added successfully!', 'success')
        
        db.session.commit()
        return redirect(url_for('dashboard'))
    
    return render_template('add_expense.html')

@app.route('/share_expense', methods=['POST'])
@login_required
def share_expense():
    expense_id = request.form['expense_id']
    email = request.form['email']
    amount = float(request.form['amount'])
    
    expense = Expense.query.get_or_404(expense_id)
    if expense.user_id != current_user.id:
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'success': False, 'message': 'User not found'})
    
    if amount > expense.amount:
        return jsonify({'success': False, 'message': 'Share amount cannot exceed expense amount'})
    
    share = ExpenseShare(
        expense_id=expense_id,
        user_id=user.id,
        amount=amount
    )
    db.session.add(share)
    db.session.commit()
    
    # Send email notification
    try:
        msg = Message(
            'New Expense Shared with You',
            sender=app.config['MAIL_USERNAME'],
            recipients=[email]
        )
        msg.body = f'''Hello,

{current_user.username} has shared an expense with you:
Description: {expense.description}
Amount: ${amount}
Category: {expense.category}

Please log in to your account to view and manage this shared expense.

Best regards,
Expense Tracker Team'''
        mail.send(msg)
    except Exception as e:
        print(f"Failed to send email: {e}")
    
    return jsonify({'success': True})

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        if not current_user.check_password(current_password):
            flash('Current password is incorrect.', 'danger')
        elif new_password != confirm_password:
            flash('New passwords do not match.', 'danger')
        else:
            current_user.set_password(new_password)
            db.session.commit()
            flash('Password updated successfully!', 'success')
    return render_template('profile.html', user=current_user)

@app.route('/mark_paid', methods=['POST'])
@login_required
def mark_paid():
    data = request.get_json()
    share_id = data.get('share_id')
    
    share = ExpenseShare.query.get_or_404(share_id)
    
    # Only the person who owes money can mark it as paid
    if share.user_id != current_user.id:
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    share.status = 'paid'
    db.session.commit()
    
    return jsonify({'success': True})

# Force table recreation on app startup (temporary fix for column size issue)
try:
    with app.app_context():
        db.drop_all()
        db.create_all()
        print("Tables dropped and recreated with correct column sizes!")
except Exception as e:
    print(f"Error recreating tables: {e}")

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)