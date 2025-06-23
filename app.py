from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
from flask_mail import Mail, Message
from sqlalchemy import text, inspect

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

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(500))
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

class GroupMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    joined_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, default=False)

class Expense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Who created the expense
    paid_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # Who actually paid for the expense
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=True)  # Make optional for backward compatibility
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # If paid_by is not specified, default to user_id
        if self.paid_by is None:
            self.paid_by = self.user_id

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
@app.route('/dashboard/<int:group_id>')
@login_required
def dashboard(group_id=None):
    try:
        # Check if groups functionality is available
        inspector = inspect(db.engine)
        tables = inspector.get_table_names()
        
        if 'group' not in tables or 'group_member' not in tables:
            # Groups functionality not available, show basic expense dashboard
            flash('Groups functionality is being set up. Showing basic expense view.', 'info')
            return render_basic_dashboard()
        
        # Get user's groups
        user_groups = db.session.query(Group).join(GroupMember).filter(
            GroupMember.user_id == current_user.id
        ).all()
        
        # If no group specified, redirect to first available group or groups page
        if group_id is None:
            if user_groups:
                return redirect(url_for('dashboard', group_id=user_groups[0].id))
            else:
                return redirect(url_for('groups'))
    except Exception as e:
        # If there's a database error (tables don't exist), show basic dashboard
        print(f"Dashboard error: {e}")
        flash('Showing basic expense view. Groups functionality will be available soon.', 'info')
        return render_basic_dashboard()
    
    # Verify user has access to this group
    current_group = None
    for group in user_groups:
        if group.id == group_id:
            current_group = group
            break
    
    if not current_group:
        flash('You do not have access to this group.', 'danger')
        return redirect(url_for('groups'))
    
    # Get expenses for current group created by current user
    expenses = Expense.query.filter_by(
        user_id=current_user.id, 
        group_id=group_id
    ).order_by(Expense.date.desc()).all()
    
    # Calculate user's share for each expense
    for expense in expenses:
        # Manually load shared expenses
        expense.shared_with = ExpenseShare.query.filter_by(expense_id=expense.id).all()
        shared_amount = sum(share.amount for share in expense.shared_with)
        expense.user_share = expense.amount - shared_amount
    
    # Get ALL expenses in this group (regardless of who created them)
    all_group_expenses = Expense.query.filter_by(group_id=group_id).order_by(Expense.date.desc()).all()
    
    # Calculate user's share for all group expenses
    for expense in all_group_expenses:
        # Manually load shared expenses
        expense.shared_with = ExpenseShare.query.filter_by(expense_id=expense.id).all()
        # Load user information for each share
        for share in expense.shared_with:
            share.user = User.query.get(share.user_id)
        
        shared_amount = sum(share.amount for share in expense.shared_with)
        if expense.paid_by == current_user.id:
            # User paid for this expense
            expense.user_share = expense.amount - shared_amount
        else:
            # Someone else paid, check if user owes anything
            user_share = next((share for share in expense.shared_with if share.user_id == current_user.id), None)
            expense.user_share = user_share.amount if user_share else 0
        
        # Load payer information manually to avoid relationship issues
        expense.payer_user = User.query.get(expense.paid_by) if expense.paid_by else None
    
    # Get expenses shared with current user in this group (where you owe money)
    # EXCLUDE expenses that you paid for yourself (you don't owe yourself money!)
    shared_expenses_owed = db.session.query(ExpenseShare).join(Expense).filter(
        ExpenseShare.user_id == current_user.id,
        Expense.group_id == group_id,
        Expense.paid_by != current_user.id  # FIXED: Don't include expenses you paid for
    ).all()
    
    # Load related data for shared expenses
    for share in shared_expenses_owed:
        share.expense = Expense.query.get(share.expense_id)
        share.expense.creator = User.query.get(share.expense.user_id)  # Who created the expense
    
    # Get expenses that current user PAID FOR where others owe money
    expenses_you_paid = Expense.query.filter_by(
        paid_by=current_user.id,
        group_id=group_id
    ).all()
    
    # Calculate what others owe you (from expenses you paid for)
    # EXCLUDE your own share from expenses you paid for
    total_owed_to_you = 0
    for expense in expenses_you_paid:
        shares = ExpenseShare.query.filter_by(expense_id=expense.id).all()
        # Only count shares from OTHER people, not yourself
        others_shares = [share for share in shares if share.user_id != current_user.id]
        total_owed_to_you += sum(share.amount for share in others_shares)
    
    # Calculate totals for this group
    # Total expenses you created (not necessarily paid for)
    total_expenses_created = sum(expense.amount for expense in expenses)
    
    # Total amount you actually paid out of pocket
    total_paid_by_you = sum(expense.amount for expense in expenses_you_paid)
    
    # Total amount you owe to others in this group (FIXED: excludes expenses you paid for)
    total_owed_by_you = sum(share.amount for share in shared_expenses_owed)
    
    # Net amount (what you owe others minus what others owe you)
    # Positive = you owe money, Negative = you are owed money
    net_balance = total_owed_by_you - total_owed_to_you
    
    # Pending payments (only what you owe to others with pending status)
    total_pending = sum(share.amount for share in shared_expenses_owed if share.status == 'pending')
    
    # Check if user is admin of current group
    user_membership = GroupMember.query.filter_by(
        group_id=group_id, 
        user_id=current_user.id
    ).first()
    is_admin = user_membership.is_admin if user_membership else False
    
    return render_template('dashboard.html',
                         expenses=all_group_expenses,
                         shared_expenses=shared_expenses_owed,
                         total_expenses=total_expenses_created,
                         total_paid_by_you=total_paid_by_you,
                         total_owed_by_you=total_owed_by_you,
                         total_owed_to_you=total_owed_to_you,
                         net_balance=net_balance,
                         total_pending=total_pending,
                         user_groups=user_groups,
                         current_group=current_group,
                         is_admin=is_admin)

def render_basic_dashboard():
    """Render a basic dashboard without groups functionality"""
    try:
        # Get basic expenses for current user (using raw SQL to avoid column issues)
        from sqlalchemy import text
        
        with db.engine.connect() as conn:
            # Get basic expense data
            result = conn.execute(text("""
                SELECT id, amount, description, category, date, user_id 
                FROM expense 
                WHERE user_id = :user_id 
                ORDER BY date DESC
            """), {"user_id": current_user.id})
            
            expenses_data = result.fetchall()
            
            # Convert to expense-like objects
            expenses = []
            total_expenses = 0
            for row in expenses_data:
                expense_obj = type('Expense', (), {
                    'id': row[0],
                    'amount': row[1],
                    'description': row[2],
                    'category': row[3],
                    'date': row[4],
                    'user_id': row[5],
                    'user_share': row[1],  # For basic view, user pays full amount
                    'shared_with': []  # No sharing in basic view
                })()
                expenses.append(expense_obj)
                total_expenses += row[1]
        
        return render_template('dashboard.html',
                             expenses=expenses,
                             shared_expenses=[],
                             total_expenses=total_expenses,
                             total_paid_by_you=total_expenses,
                             total_owed_by_you=0,
                             total_owed_to_you=0,
                             net_balance=0,
                             total_pending=0,
                             user_groups=[],
                             current_group=None,
                             is_admin=False)
    except Exception as e:
        print(f"Basic dashboard error: {e}")
        # Return minimal dashboard
        return render_template('dashboard.html',
                             expenses=[],
                             shared_expenses=[],
                             total_expenses=0,
                             total_paid_by_you=0,
                             total_owed_by_you=0,
                             total_owed_to_you=0,
                             net_balance=0,
                             total_pending=0,
                             user_groups=[],
                             current_group=None,
                             is_admin=False)

@app.route('/groups')
@login_required
def groups():
    try:
        # Get user's groups
        user_groups = db.session.query(Group).join(GroupMember).filter(
            GroupMember.user_id == current_user.id
        ).all()
        
        return render_template('groups.html', user_groups=user_groups)
    except Exception as e:
        print(f"Groups page error: {e}")
        # If tables don't exist, show empty groups page
        return render_template('groups.html', user_groups=[])

@app.route('/create_group', methods=['GET', 'POST'])
@login_required
def create_group():
    if request.method == 'POST':
        try:
            name = request.form['name']
            description = request.form.get('description', '')
            
            # Create the group
            group = Group(
                name=name,
                description=description,
                created_by=current_user.id
            )
            db.session.add(group)
            db.session.flush()  # Get the group ID
            
            # Add creator as admin member
            membership = GroupMember(
                group_id=group.id,
                user_id=current_user.id,
                is_admin=True
            )
            db.session.add(membership)
            db.session.commit()
            
            flash(f'Group "{name}" created successfully!', 'success')
            return redirect(url_for('dashboard', group_id=group.id))
        except Exception as e:
            db.session.rollback()
            print(f"Create group error: {e}")
            flash('Error creating group. Please ensure the database is properly set up.', 'danger')
            return render_template('create_group.html')
    
    return render_template('create_group.html')

@app.route('/join_group', methods=['POST'])
@login_required
def join_group():
    group_id = request.form['group_id']
    
    # Check if group exists
    group = Group.query.get_or_404(group_id)
    
    # Check if user is already a member
    existing_membership = GroupMember.query.filter_by(
        group_id=group_id,
        user_id=current_user.id
    ).first()
    
    if existing_membership:
        flash('You are already a member of this group.', 'warning')
    else:
        # Add user to group
        membership = GroupMember(
            group_id=group_id,
            user_id=current_user.id,
            is_admin=False
        )
        db.session.add(membership)
        db.session.commit()
        
        flash(f'Successfully joined group "{group.name}"!', 'success')
    
    return redirect(url_for('dashboard', group_id=group_id))

@app.route('/manage_group/<int:group_id>')
@login_required
def manage_group(group_id):
    # Check if user is admin of this group
    membership = GroupMember.query.filter_by(
        group_id=group_id,
        user_id=current_user.id,
        is_admin=True
    ).first()
    
    if not membership:
        flash('You do not have permission to manage this group.', 'danger')
        return redirect(url_for('dashboard', group_id=group_id))
    
    group = Group.query.get_or_404(group_id)
    members = db.session.query(User, GroupMember).join(GroupMember).filter(
        GroupMember.group_id == group_id
    ).all()
    
    return render_template('manage_group.html', group=group, members=members)

@app.route('/add_member', methods=['POST'])
@login_required
def add_member():
    group_id = request.form['group_id']
    email = request.form['email']
    
    # Check if user is admin of this group
    membership = GroupMember.query.filter_by(
        group_id=group_id,
        user_id=current_user.id,
        is_admin=True
    ).first()
    
    if not membership:
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    # Find user by email
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'success': False, 'message': 'User not found'})
    
    # Check if user is already a member
    existing_membership = GroupMember.query.filter_by(
        group_id=group_id,
        user_id=user.id
    ).first()
    
    if existing_membership:
        return jsonify({'success': False, 'message': 'User is already a member'})
    
    # Add user to group
    new_membership = GroupMember(
        group_id=group_id,
        user_id=user.id,
        is_admin=False
    )
    db.session.add(new_membership)
    db.session.commit()
    
    return jsonify({'success': True, 'message': f'{user.username} added to group'})

@app.route('/remove_member', methods=['POST'])
@login_required
def remove_member():
    data = request.get_json()
    group_id = data.get('group_id')
    user_id = data.get('user_id')
    
    # Check if user is admin of this group
    admin_membership = GroupMember.query.filter_by(
        group_id=group_id,
        user_id=current_user.id,
        is_admin=True
    ).first()
    
    if not admin_membership:
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    # Cannot remove the group creator
    group = Group.query.get_or_404(group_id)
    if group.created_by == user_id:
        return jsonify({'success': False, 'message': 'Cannot remove group creator'})
    
    # Remove user from group
    membership = GroupMember.query.filter_by(
        group_id=group_id,
        user_id=user_id
    ).first()
    
    if membership:
        db.session.delete(membership)
        db.session.commit()
        return jsonify({'success': True})
    else:
        return jsonify({'success': False, 'message': 'User not found in group'})

@app.route('/delete_group', methods=['POST'])
@login_required
def delete_group():
    data = request.get_json()
    group_id = data.get('group_id')
    
    group = Group.query.get_or_404(group_id)
    
    # Only group creator can delete the group
    if group.created_by != current_user.id:
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    try:
        # Delete all group expenses and their shares
        expenses = Expense.query.filter_by(group_id=group_id).all()
        for expense in expenses:
            ExpenseShare.query.filter_by(expense_id=expense.id).delete()
            db.session.delete(expense)
        
        # Delete all group memberships
        GroupMember.query.filter_by(group_id=group_id).delete()
        
        # Delete the group
        db.session.delete(group)
        db.session.commit()
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/add_expense/<int:group_id>', methods=['GET', 'POST'])
@login_required
def add_expense(group_id):
    # Verify user has access to this group
    membership = GroupMember.query.filter_by(
        group_id=group_id,
        user_id=current_user.id
    ).first()
    
    if not membership:
        flash('You do not have access to this group.', 'danger')
        return redirect(url_for('groups'))
    
    group = Group.query.get_or_404(group_id)
    
    # Get ALL group members (including current user) for paid_by dropdown
    all_group_members = db.session.query(User).join(GroupMember).filter(
        GroupMember.group_id == group_id
    ).all()
    
    # Get group members excluding current user for sharing dropdown
    other_group_members = db.session.query(User).join(GroupMember).filter(
        GroupMember.group_id == group_id,
        User.id != current_user.id
    ).all()
    
    if request.method == 'POST':
        amount = float(request.form['amount'])
        description = request.form['description']
        category = request.form['category']
        paid_by_id = int(request.form['paid_by'])  # NEW: Get who paid for the expense
        
        # Verify the paid_by user is a member of this group
        paid_by_user = db.session.query(User).join(GroupMember).filter(
            User.id == paid_by_id,
            GroupMember.group_id == group_id
        ).first()
        
        if not paid_by_user:
            flash('Invalid payer selected.', 'danger')
            return redirect(url_for('add_expense', group_id=group_id))
        
        # Check if expense should be split across multiple members
        split_expense = request.form.get('split_expense')
        split_count = request.form.get('split_count')
        
        # Create the expense with group_id and paid_by
        expense = Expense(
            amount=amount,
            description=description,
            category=category,
            user_id=current_user.id,  # Who created the expense entry
            paid_by=paid_by_id,       # Who actually paid for the expense
            group_id=group_id
        )
        db.session.add(expense)
        db.session.flush()  # Get the expense ID
        
        # Handle multiple member splitting if requested
        if split_expense and split_count:
            try:
                split_count_int = int(split_count)
                total_shared = 0
                shared_members = []
                
                for i in range(split_count_int):
                    member_id = request.form.get(f'split_member_{i}')
                    member_email = request.form.get(f'split_email_{i}')
                    split_amount = request.form.get(f'split_amount_{i}')
                    
                    if member_id and split_amount:
                        member_id_int = int(member_id)
                        split_amount_float = float(split_amount)
                        
                        # Verify the member is in the group
                        member_user = db.session.query(User).join(GroupMember).filter(
                            User.id == member_id_int,
                            GroupMember.group_id == group_id
                        ).first()
                        
                        if member_user:
                            # Create the expense share
                            expense_share = ExpenseShare(
                                expense_id=expense.id,
                                user_id=member_id_int,
                                amount=split_amount_float
                            )
                            db.session.add(expense_share)
                            total_shared += split_amount_float
                            shared_members.append(member_user.username)
                
                # Send email notifications if configured
                try:
                    if app.config['MAIL_USERNAME'] and shared_members:
                        for i in range(split_count_int):
                            member_email = request.form.get(f'split_email_{i}')
                            split_amount = request.form.get(f'split_amount_{i}')
                            
                            if member_email and split_amount:
                                msg = Message(
                                    'Expense Split with You',
                                    sender=app.config['MAIL_USERNAME'],
                                    recipients=[member_email]
                                )
                                msg.body = f'''Hello,

{current_user.username} has split an expense with you in group "{group.name}":
Description: {description}
Total Amount: ${amount}
Paid by: {paid_by_user.username}
Your Share: ${split_amount}
Category: {category}
Split among: {', '.join(shared_members)}

Please log in to your account to view and manage this shared expense.

Best regards,
Expense Tracker Team'''
                                mail.send(msg)
                except Exception as e:
                    print(f"Failed to send email: {e}")
                
                if shared_members:
                    flash(f'Expense added and split among {len(shared_members)} members: {", ".join(shared_members)}!', 'success')
                else:
                    flash('Expense added but no valid members found for splitting.', 'warning')
                    
            except (ValueError, TypeError) as e:
                flash('Error processing split amounts. Expense added but not split.', 'warning')
                print(f"Split processing error: {e}")
        else:
            flash('Expense added successfully!', 'success')
        
        db.session.commit()
        return redirect(url_for('dashboard', group_id=group_id))
    
    return render_template('add_expense.html', 
                         group=group, 
                         all_group_members=all_group_members,
                         other_group_members=other_group_members,
                         current_user=current_user)

@app.route('/share_expense', methods=['POST'])
@login_required
def share_expense():
    expense_id = request.form['expense_id']
    email = request.form['email']
    amount = float(request.form['amount'])
    
    expense = Expense.query.get_or_404(expense_id)
    if expense.user_id != current_user.id:
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    # Find user and verify they are in the same group
    user = db.session.query(User).join(GroupMember).filter(
        User.email == email,
        GroupMember.group_id == expense.group_id
    ).first()
    
    if not user:
        return jsonify({'success': False, 'message': 'User not found in this group'})
    
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
        if app.config['MAIL_USERNAME']:
            msg = Message(
                'New Expense Shared with You',
                sender=app.config['MAIL_USERNAME'],
                recipients=[email]
            )
            msg.body = f'''Hello,

{current_user.username} has shared an expense with you in group "{expense.group.name}":
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

@app.route('/edit_expense', methods=['POST'])
@login_required
def edit_expense():
    expense_id = request.form.get('expense_id')
    description = request.form.get('description')
    amount = request.form.get('amount')
    category = request.form.get('category')
    
    expense = Expense.query.get_or_404(expense_id)
    
    # Only the owner can edit the expense
    if expense.user_id != current_user.id:
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    try:
        expense.description = description
        expense.amount = float(amount)
        expense.category = category
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/delete_expense', methods=['POST'])
@login_required
def delete_expense():
    data = request.get_json()
    expense_id = data.get('expense_id')
    
    expense = Expense.query.get_or_404(expense_id)
    
    # Only the owner can delete the expense
    if expense.user_id != current_user.id:
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    try:
        # Delete associated expense shares first
        ExpenseShare.query.filter_by(expense_id=expense_id).delete()
        # Delete the expense
        db.session.delete(expense)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

# Create tables if they don't exist
def create_tables():
    """Create database tables with error handling"""
    try:
        # Simple approach: just create all tables
        db.create_all()
        print("✅ Database tables created/verified successfully")
        
        # Run migration to add missing columns
        migrate_existing_tables()
        
    except Exception as e:
        print(f"❌ Error creating database tables: {e}")
        # Don't fail the app startup, just log the error

def migrate_existing_tables():
    """Add missing columns to existing tables"""
    try:
        inspector = inspect(db.engine)
        
        # Check if expense table exists and what columns it has
        if 'expense' in inspector.get_table_names():
            expense_columns = [col['name'] for col in inspector.get_columns('expense')]
            
            with db.engine.connect() as conn:
                trans = conn.begin()
                try:
                    # Add paid_by column if it doesn't exist
                    if 'paid_by' not in expense_columns:
                        print("Adding paid_by column to expense table...")
                        conn.execute(text("ALTER TABLE expense ADD COLUMN paid_by INTEGER"))
                        conn.execute(text("UPDATE expense SET paid_by = user_id WHERE paid_by IS NULL"))
                        print("✅ Added paid_by column")
                    
                    # Add group_id column if it doesn't exist
                    if 'group_id' not in expense_columns:
                        print("Adding group_id column to expense table...")
                        conn.execute(text("ALTER TABLE expense ADD COLUMN group_id INTEGER"))
                        print("✅ Added group_id column")
                    
                    trans.commit()
                    print("✅ Table migration completed")
                    
                except Exception as e:
                    trans.rollback()
                    print(f"❌ Migration failed: {e}")
                    
    except Exception as e:
        print(f"❌ Migration error: {e}")

def ensure_basic_functionality():
    """Ensure the app can run even if groups functionality isn't available"""
    try:
        # Test basic database connection
        with db.engine.connect() as conn:
            # Check if user table exists (most basic requirement)
            result = conn.execute(db.text("SELECT 1"))
            result.fetchone()
        print("✅ Database connection verified")
    except Exception as e:
        print(f"❌ Database connection failed: {e}")

# AI-powered endpoints
@app.route('/parse_ai_expense', methods=['POST'])
@login_required
def parse_ai_expense():
    """Parse natural language expense description using OpenAI"""
    try:
        import openai
        
        data = request.get_json()
        text = data.get('text', '').strip()
        group_id = data.get('group_id')
        
        if not text:
            return jsonify({'success': False, 'error': 'No text provided'})
        
        # Get OpenAI API key from environment
        openai_key = os.environ.get('OPENAI_API_KEY')
        if not openai_key:
            return jsonify({'success': False, 'error': 'OpenAI API key not configured'})
        
        # Get group members for context
        group_members = []
        if group_id:
            members = db.session.query(User).join(GroupMember).filter(
                GroupMember.group_id == group_id
            ).all()
            group_members = [{'id': m.id, 'name': m.username, 'email': m.email} for m in members]
        
        # Create OpenAI client
        client = openai.OpenAI(api_key=openai_key)
        
        # Create the prompt
        prompt = f"""Parse this expense description into structured data:
"{text}"

Available group members: {[m['name'] for m in group_members]}
Current user: {current_user.username}

Return JSON with:
- description: clear expense description
- amount: numeric amount (extract from text)
- category: one of [Food, Transportation, Housing, Utilities, Entertainment, Shopping, Healthcare, Education, Other]
- paid_by: who paid (use member name or "current_user" if unclear)
- splits: array of {{"user_name": "name", "amount": number}} for who owes what

Examples:
"Pizza $45 split equally with John" → paid_by: "current_user", splits: [{{"user_name": "John", "amount": 22.5}}]
"Uber $20 paid by Sarah" → paid_by: "Sarah", splits: [{{"user_name": "current_user", "amount": 20}}]
"""

        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are an expense parsing assistant. Always return valid JSON."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.1
        )
        
        # Parse the response
        import json
        ai_response = response.choices[0].message.content.strip()
        
        # Clean up the response if it has markdown formatting
        if ai_response.startswith('```json'):
            ai_response = ai_response[7:-3]
        elif ai_response.startswith('```'):
            ai_response = ai_response[3:-3]
        
        parsed_expense = json.loads(ai_response)
        
        # Validate and clean the data
        expense_data = {
            'description': parsed_expense.get('description', text)[:200],
            'amount': float(parsed_expense.get('amount', 0)),
            'category': parsed_expense.get('category', 'Other'),
            'paid_by': parsed_expense.get('paid_by', 'current_user'),
            'splits': parsed_expense.get('splits', []),
            'group_id': group_id
        }
        
        # Convert paid_by to user ID
        if expense_data['paid_by'] == 'current_user':
            expense_data['paid_by_id'] = current_user.id
            expense_data['paid_by'] = current_user.username
        else:
            # Find the user by name
            paid_by_user = next((m for m in group_members if m['name'].lower() == expense_data['paid_by'].lower()), None)
            if paid_by_user:
                expense_data['paid_by_id'] = paid_by_user['id']
            else:
                expense_data['paid_by_id'] = current_user.id
                expense_data['paid_by'] = current_user.username
        
        # Convert split user names to IDs
        for split in expense_data['splits']:
            if split['user_name'] == 'current_user':
                split['user_id'] = current_user.id
                split['user_name'] = current_user.username
            else:
                split_user = next((m for m in group_members if m['name'].lower() == split['user_name'].lower()), None)
                if split_user:
                    split['user_id'] = split_user['id']
                else:
                    split['user_id'] = None  # Invalid user
        
        return jsonify({'success': True, 'expense': expense_data})
        
    except ImportError:
        return jsonify({'success': False, 'error': 'OpenAI library not installed'})
    except json.JSONDecodeError as e:
        return jsonify({'success': False, 'error': f'Failed to parse AI response: {str(e)}'})
    except Exception as e:
        return jsonify({'success': False, 'error': f'AI parsing failed: {str(e)}'})

@app.route('/create_ai_expense', methods=['POST'])
@login_required
def create_ai_expense():
    """Create an expense from AI-parsed data"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['description', 'amount', 'category', 'paid_by_id', 'group_id']
        for field in required_fields:
            if field not in data:
                return jsonify({'success': False, 'error': f'Missing field: {field}'})
        
        # Create the expense
        expense = Expense(
            amount=float(data['amount']),
            description=data['description'],
            category=data['category'],
            user_id=current_user.id,
            paid_by=data['paid_by_id'],
            group_id=data['group_id']
        )
        db.session.add(expense)
        db.session.flush()  # Get the expense ID
        
        # Create expense shares
        total_shared = 0
        for split in data.get('splits', []):
            if split.get('user_id') and split.get('amount'):
                expense_share = ExpenseShare(
                    expense_id=expense.id,
                    user_id=split['user_id'],
                    amount=float(split['amount'])
                )
                db.session.add(expense_share)
                total_shared += float(split['amount'])
        
        db.session.commit()
        
        return jsonify({
            'success': True, 
            'message': f'Expense created successfully! Total shared: ${total_shared:.2f}'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': f'Failed to create expense: {str(e)}'})

if __name__ == '__main__':
    with app.app_context():
        create_tables()
        ensure_basic_functionality()
    app.run(debug=True)
else:
    # When running in production (like Render), create tables on startup
    with app.app_context():
        create_tables()
        ensure_basic_functionality()