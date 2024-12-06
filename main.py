import random
from bson import ObjectId
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from pymongo import MongoClient
from flask_bcrypt import Bcrypt
import secrets
from datetime import datetime, timedelta

app = Flask(__name__, static_url_path='/static', static_folder='static')
app.secret_key = 'your_secret_key'
bcrypt = Bcrypt(app)

# MongoDB configuration
client = MongoClient('mongodb://localhost:27017/')
db = client['adb']
users_collection = db['customers']
admin_users_collection = db['admin']
bank_officers_collection = db['bankofficer']
transactions_collection = db['transactions']
accounts_collection = db['accounts']
banks_collection = db['banks']


class User:
    def __init__(self, username, password):
        self.username = username
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')


@app.route('/')
def home():
    return redirect(url_for('login'))
from bson import ObjectId
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Collect form data
        fname = request.form.get('fname')
        lname = request.form.get('lname')
        dob = request.form.get('dob')
        address = request.form.get('address')
        contact = request.form.get('contact')
        ssn = request.form.get('ssn')
        username = request.form.get('username')
        password = request.form.get('password')
        cpassword = request.form.get('cpassword')

        # Hardcoded bank_id for American Express
        bank_id = ObjectId("66d6aa3e41d3ab778b27b6f5")

        # Validate fields
        if not all([fname, lname, dob, address, contact, ssn, username, password, cpassword]):
            flash('All fields are required', 'error')
            return redirect(url_for('register'))

        # Validate SSN
        if not (ssn.isdigit() and len(ssn) == 9):
            flash('SSN must be exactly 9 digits long and contain only numbers', 'error')
            return redirect(url_for('register'))

        # Check if passwords match
        if password != cpassword:
            flash('Password and Confirm Password do not match', 'error')
            return redirect(url_for('register'))

        # Enforce strong password policy
        if len(password) < 8:
            flash('Password must be at least 8 characters long', 'error')
            return redirect(url_for('register'))

        # Check for duplicate username
        existing_user = users_collection.find_one({"username": username})
        if existing_user:
            flash('Username already exists', 'error')
            return redirect(url_for('register'))

        # Hash the password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Create user document
        user = {
            "fname": fname,
            "lname": lname,
            "dob": dob,
            "address": address,
            "contact": contact,
            "ssn": ssn,
            "username": username,
            "password": hashed_password,
            "bank_id": bank_id,  # Store the bank's ObjectId in the user document
            "isActive": False  # Set account activation logic
        }

        user_inserted = users_collection.insert_one(user)

        # Generate account-related details
        account_number = ''.join([str(random.randint(0, 9)) for _ in range(12)])
        debit_card_number = ''.join([str(random.randint(0, 9)) for _ in range(16)])
        cvv = ''.join([str(random.randint(0, 9)) for _ in range(3)])  # Generate CVV
        expire_month = str(random.randint(1, 12)).zfill(2)  # Ensures 2-digit month
        expire_year = str(datetime.now().year + random.randint(1, 5))  # Valid for 1-5 years

        # Create an account for the user with a minimum deposit of $100
        account = {
            "accountNumber": account_number,
            "CustomerId": user_inserted.inserted_id,
            "balance": 100.00,  # Initial deposit of $100
            "debitCard": debit_card_number,
            "cvv": cvv,
            "expireMonth": expire_month,
            "expireYear": expire_year,
            "bankId": bank_id,
            "Enable_Overdraft": False,
            "overdraftStart": None
        }
        accounts_collection.insert_one(account)

        # Add a transaction for the initial deposit
        transaction = {
            "accountId": account_number,
            "senderAccount": "Bank",
            "amount": 100.00,
            "type": "New Account Minimum Deposit",
            "dateTime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        transactions_collection.insert_one(transaction)

        flash('Registration successful. A minimum deposit of $100 has been added to your account.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/approve_users')
def approve_users():
    if 'username' in session and session['user_type'] == 'admin':
        username = session['username']
        unapproved_users = users_collection.find({"isActive": False})
        return render_template('approve_users.html', users=unapproved_users, username=username)
    else:
        return redirect(url_for('login'))
@app.route('/approve_user/<user_id>', methods=['GET', 'POST'])
def approve_user(user_id):
    if 'username' in session and session['user_type'] == 'admin':
        username = session['username']
        user = users_collection.find_one({'_id': ObjectId(user_id)})

        if not user:
            flash('User not found.', 'error')
            return redirect(url_for('approve_users'))

        if request.method == 'POST':
            enable_overdraft = request.form.get('enable_overdraft') == 'on'  # Checkbox for overdraft

            # Update user as active
            users_collection.update_one(
                {'_id': ObjectId(user_id)},
                {'$set': {'isActive': True}}
            )

            # Retrieve the account associated with the user
            account = accounts_collection.find_one({'CustomerId': ObjectId(user_id)})

            if not account:
                flash('No associated account found for this user.', 'error')
                return redirect(url_for('approve_users'))

            # Update account details for overdraft
            accounts_collection.update_one(
                {'CustomerId': ObjectId(user_id)},
                {'$set': {'Enable_Overdraft': enable_overdraft}}
            )

            # Add the minimum deposit transaction and update balance
            minimum_deposit = 100.00
            new_balance = account.get('balance', 0) + minimum_deposit

            # Update account balance
            accounts_collection.update_one(
                {'CustomerId': ObjectId(user_id)},
                {'$set': {'balance': new_balance}}
            )

            # Record the minimum deposit transaction
            transaction = {
                "accountId": account['accountNumber'],
                "senderAccount": "Bank",
                "amount": minimum_deposit,
                "type": "New Account Minimum Deposit",
                "dateTime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            transactions_collection.insert_one(transaction)

            flash('User approved successfully. Minimum deposit of $100 has been added.', 'success')
            return redirect(url_for('approve_users'))

        # Fetch additional account and bank details for the approval form
        account = accounts_collection.find_one({'CustomerId': ObjectId(user_id)})
        bank = banks_collection.find_one({'_id': account['bankId']}) if account else None

        return render_template(
            'approve_user.html',
            user=user,
            account=account,
            bank=bank,
            username=username
        )

    else:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('login'))


@app.route('/deposit_money', methods=['GET', 'POST'])
def deposit_money():
    if 'username' in session and session['user_type'] == 'admin':
        username = session['username']
        if request.method == 'POST':
            account_number = request.form.get('account_number')
            first_name = request.form.get('first_name')
            last_name = request.form.get('last_name')
            deposit_amount = float(request.form.get('deposit_amount'))

            # Fetch the account and customer data
            account = db['accounts'].find_one({'accountNumber': account_number})
            if account:
                user = db['customers'].find_one({'_id': account['CustomerId']})

                # Check if the provided first and last name match the customer
                if user and user.get('fname') == first_name and user.get('lname') == last_name:
                    # Process deposit
                    new_balance = account['balance'] + deposit_amount
                    db['accounts'].update_one({'accountNumber': account_number}, {'$set': {'balance': new_balance}})

                    # Record the deposit transaction
                    transaction_credit = {
                        "accountId": account_number,
                        "senderAccount": "Bank Officer - " + session['username'],  # Identifies the bank officer
                        "amount": round(deposit_amount, 2),
                        "type": "Deposit",
                        "dateTime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }
                    db['transactions'].insert_one(transaction_credit)

                    flash('Deposit successful', 'success')
                else:
                    flash('Customer name does not match account details', 'error')
            else:
                flash('Account not found', 'error')

            return redirect(url_for('deposit_money'))

        return render_template('deposit_money.html', username=username)
    else:
        return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Check if the user is an admin
        admin_user = admin_users_collection.find_one({'username': username})
        if admin_user and bcrypt.check_password_hash(admin_user['password'], password):
            session['username'] = username
            session['user_type'] = 'admin'  # Set user type to 'admin'
            return redirect(url_for('admin_dashboard'))

        # Check if the user is an admin
        bank_officer = bank_officers_collection.find_one({'username': username})
        if bank_officer and bcrypt.check_password_hash(bank_officer['password'], password):
            session['username'] = username
            session['user_type'] = 'admin'  # Set user type to 'admin'
            return redirect(url_for('bankofficer_dashboard'))

        user = users_collection.find_one({'username': username})
        if user and bcrypt.check_password_hash(user['password'], password):
            if user.get('isActive', False):  # Check if user is approved
                session['username'] = username
                return redirect(url_for('dashboard'))
            else:
                flash('Account not yet approved by admin', 'error')
                return redirect(url_for('login'))

        flash('Invalid username or password', 'error')  # Flash message for invalid login

    return render_template('login.html')
@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        username = session['username']
        user = users_collection.find_one({'username': username})

        if user:
            customer_id = user['_id']

            # Fetch all accounts associated with the user
            accounts = list(accounts_collection.find({'CustomerId': customer_id}))

            # Initialize account details and transactions
            account_details = {}
            transactions = []

            # Attach bank details and additional account details (CVV, Expiry) to each account
            for account in accounts:
                bank = banks_collection.find_one({'_id': account['bankId']})
                account['bankName'] = bank['name'] if bank else 'Unknown Bank'

                # Fetch and format transactions for the account
                account_transactions = list(transactions_collection.find({
                    '$or': [
                        {'accountId': account["accountNumber"]},  # Credit transactions
                        {'receiverAccount': account["accountNumber"]}  # Debit transactions
                    ]
                }).sort('dateTime', -1))

                for transaction in account_transactions:
                    if isinstance(transaction['dateTime'], str):
                        transaction_datetime = datetime.strptime(transaction['dateTime'], "%Y-%m-%d %H:%M:%S")
                    else:
                        transaction_datetime = transaction['dateTime']

                    # Format dateTime to include seconds
                    transaction['dateTime'] = transaction_datetime.strftime('%I:%M:%S %p %d-%m-%Y')

                # Add transactions to account
                account['transactions'] = account_transactions
                transactions.extend(account_transactions)

                # Prepare account details+-+++--
                account_details = {
                    'fname': user.get('fname', 'N/A'),
                    'lname': user.get('lname', 'N/A'),
                    'balance': account.get('balance', 0.0),
                    'debitCardNumber': account.get('debitCard', 'N/A'),
                    'cvv': account.get('cvv', 'N/A'),
                    'expireMonth': account.get('expireMonth', 'N/A'),
                    'expireYear': account.get('expireYear', 'N/A'),
                    'accountNumber': account.get('accountNumber', 'N/A'),
                    'address': user.get('address', 'N/A'),
                    'ssn': user.get('ssn', 'N/A'),
                    'bankName': account.get('bankName', 'Unknown Bank'),
                }

            return render_template(
                'dashboard.html',
                username=username,
                accounts=accounts,
                account_details=account_details,
                transactions=transactions
            )

        else:
            flash("User not found!", "error")
            return redirect(url_for('login'))
    else:
        return redirect(url_for('login'))

@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    if 'username' in session:
        username = session['username']
        user = users_collection.find_one({'username': username})

        if request.method == 'POST':
            sender_account_number = request.form.get('sender_account')
            receiver_account_number = request.form.get('receiver_account')
            amount = float(request.form.get('amount'))

            if amount <= 0:
                flash('Amount must be greater than zero', 'error')
                return redirect(url_for('transfer'))

            if sender_account_number == receiver_account_number:
                flash('Cannot transfer to the same account', 'error')
                return redirect(url_for('transfer'))

            sender_account = db['accounts'].find_one({'accountNumber': sender_account_number})
            receiver_account = db['accounts'].find_one({'accountNumber': receiver_account_number})

            if not receiver_account:
                flash('Invalid receiver account number', 'error')
                return redirect(url_for('transfer'))

            if sender_account:
                overdraft_enabled = sender_account.get('Enable_Overdraft', False)
                available_balance = sender_account['balance']

                # Include overdraft limit if applicable
                overdraft_limit = sender_account.get('overdraftLimit', 1000) if overdraft_enabled else 0
                available_balance += overdraft_limit

                if available_balance >= amount:
                    # Deduct amount from sender and add to receiver
                    new_sender_balance = sender_account['balance'] - amount
                    db['accounts'].update_one(
                        {'accountNumber': sender_account_number},
                        {'$set': {'balance': new_sender_balance}}
                    )
                    db['accounts'].update_one(
                        {'accountNumber': receiver_account_number},
                        {'$inc': {'balance': amount}}
                    )

                    # Record transactions
                    transaction_debit = {
                        "accountId": sender_account_number,
                        "receiverAccount": receiver_account_number,
                        "amount": -round(amount, 2),
                        "type": "Transfer Debit",
                        "dateTime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }
                    transaction_credit = {
                        "accountId": receiver_account_number,
                        "senderAccount": sender_account_number,
                        "amount": round(amount, 2),
                        "type": "Transfer Credit",
                        "dateTime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }
                    db['transactions'].insert_one(transaction_debit)
                    db['transactions'].insert_one(transaction_credit)

                    # Check and apply overdraft fee
                    if overdraft_enabled and new_sender_balance < 0:
                        overdraft_start = sender_account.get('overdraftStart')
                        now = datetime.now()

                        # Ensure overdraftStart is either None or properly set as datetime
                        if not overdraft_start:
                            db['accounts'].update_one(
                                {'accountNumber': sender_account_number},
                                {'$set': {'overdraftStart': now}}
                            )
                        else:
                            # Handle case where overdraftStart might already be a datetime object
                            if isinstance(overdraft_start, str):
                                overdraft_start = datetime.strptime(overdraft_start, "%Y-%m-%d %H:%M:%S")

                            # Check if 24 hours have passed
                            if now - overdraft_start > timedelta(hours=24):
                                # Apply $35 overdraft fee
                                new_sender_balance -= 35
                                db['accounts'].update_one(
                                    {'accountNumber': sender_account_number},
                                    {'$set': {'balance': new_sender_balance, 'overdraftStart': now}}
                                )
                                overdraft_fee_transaction = {
                                    "accountId": sender_account_number,
                                    "receiverAccount": "Bank",
                                    "amount": -35,
                                    "type": "Overdraft Fee",
                                    "dateTime": now.strftime("%Y-%m-%d %H:%M:%S")
                                }
                                db['transactions'].insert_one(overdraft_fee_transaction)

                    flash('Transfer completed successfully', 'success')
                else:
                    flash('Insufficient funds (including overdraft limit)', 'error')
            else:
                flash('Sender account not found', 'error')

            return redirect(url_for('transfer'))

        if user:
            customer_id = user['_id']
            account = db['accounts'].find_one({'CustomerId': customer_id})

            if account:
                user_account_number = account['accountNumber']
                balance = round(account['balance'], 2)
                return render_template('transfer.html', username=username, user_account_number=user_account_number,
                                       balance=balance)
            else:
                return 'No account found for the user'
        else:
            return redirect(url_for('login'))

    return render_template('transfer.html', username=session['username'])

@app.route('/admin_dashboard')
def admin_dashboard():
    if 'username' in session and session['user_type'] == 'admin':
        username = session['username']
        total_users = users_collection.count_documents({})
        bank_officers = bank_officers_collection.count_documents({})
        total_transactions = transactions_collection.count_documents({})

        return render_template(
            'admin_dashboard.html',
            username=username,
            total_users=total_users,
            bank_officers=bank_officers,
            total_transactions=total_transactions
        )
    else:
        flash('Unauthorized access. Please log in as admin.', 'error')
        return redirect(url_for('login'))

@app.route('/bankofficer_dashboard')
def bankofficer_dashboard():
    if 'username' in session and session['user_type'] == 'admin':
        total_users = users_collection.count_documents({})
        bank_officers = bank_officers_collection.count_documents({})
        total_transactions = transactions_collection.count_documents({})

        return render_template('bankofficer_dashboard.html',
                               username=session['username'],
                               total_users=total_users,
                               bank_officers=bank_officers,
                               total_transactions=total_transactions)
    else:
        return redirect(url_for('login'))

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'username' in session:  # Check if the user is logged in
        username = session['username']

        if request.method == 'POST':
            # Collect form data
            current_password = request.form.get('current_password')
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')

            # Retrieve the user's details from the database
            bank_officer = bank_officers_collection.find_one({'username': username})

            # Validate current password
            if not bank_officer or not bcrypt.check_password_hash(bank_officer['password'], current_password):
                flash('Current password is incorrect', 'error')
                return redirect(url_for('change_password'))

            # Validate new password and confirmation match
            if new_password != confirm_password:
                flash('New password and confirm password do not match', 'error')
                return redirect(url_for('change_password'))

            # Enforce password policy
            if len(new_password) < 8:
                flash('Password must be at least 8 characters long', 'error')
                return redirect(url_for('change_password'))

            # Update the user's password in the database
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            bank_officers_collection.update_one({'username': username}, {'$set': {'password': hashed_password}})

            flash('Password changed successfully', 'success')
            return redirect(url_for('bankofficer_dashboard'))

        return render_template('change_password.html', username=username)

    flash('You must log in to access this page', 'error')
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))


@app.route('/ecommerce')
def ecommerce():
    return render_template('ecommerce/index.html')

@app.route('/payment')
def payment():
    price = request.args.get('price', '0.00')  # Default to 0.00 if not provided
    return render_template('ecommerce/payment.html', price=price)


@app.route('/process_payment', methods=['POST'])
def process_payment():
    try:
        # Fetch payment details from the form
        debit_card_number = request.form.get('debitCardNumber')
        card_name = request.form.get('cardname')
        exp_month = request.form.get('expmonth')
        exp_year = request.form.get('expyear')
        cvv = request.form.get('cvv')
        amount = float(request.form.get('amount'))

        # Validate input
        if not all([debit_card_number, card_name, exp_month, exp_year, cvv]) or amount <= 0:
            return jsonify({'status': 'error', 'message': 'All fields are required'}), 400

        # Fetch the account by debit card number
        account = db['accounts'].find_one({'debitCard': debit_card_number})

        if not account:
            return jsonify({'status': 'error', 'message': 'Invalid debit card number'}), 404

        # Fetch user details
        customer_id = account.get('CustomerId')
        user = db['customers'].find_one({'_id': customer_id})
        if not user:
            return jsonify({'status': 'error', 'message': 'User not found'}), 404

        # Validate name on card
        expected_name = f"{user.get('fname', '').strip()} {user.get('lname', '').strip()}".strip()
        if card_name != expected_name:
            return jsonify({'status': 'error', 'message': 'Name on card does not match'}), 400

        # Validate expiration date
        stored_exp_month = account.get('expireMonth')
        stored_exp_year = account.get('expireYear')
        if f"{exp_month}/{exp_year}" != f"{stored_exp_month}/{stored_exp_year}":
            return jsonify({'status': 'error', 'message': 'Expiration date does not match'}), 400

        # Validate CVV
        stored_cvv = account.get('cvv')
        if cvv != stored_cvv:
            return jsonify({'status': 'error', 'message': 'Invalid CVV'}), 400

        # Check balance and overdraft status
        balance = account.get('balance', 0.0)
        overdraft_enabled = account.get('Enable_Overdraft', False)
        overdraft_limit = account.get('overdraftLimit', 1000) if overdraft_enabled else 0
        available_funds = balance + overdraft_limit

        if available_funds >= amount:
            # Deduct the amount from the balance
            new_balance = balance - amount
            update_fields = {'balance': new_balance}

            # Set overdraftStart if the balance becomes negative and overdraft is enabled
            if overdraft_enabled and new_balance < 0 and not account.get('overdraftStart'):
                update_fields['overdraftStart'] = datetime.now()

            db['accounts'].update_one(
                {'debitCard': debit_card_number},
                {'$set': update_fields}
            )

            # Record the transaction
            transaction = {
                "accountId": account['accountNumber'],
                "receiverAccount": "Online Ecommerce",
                "amount": -amount,
                "type": "Debit Card Purchase",
                "dateTime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "transactionId": str(ObjectId())  # Unique transaction ID
            }
            db['transactions'].insert_one(transaction)

            # Generate a unique redirect ID for success
            success_id = str(ObjectId())
            session['transaction_details'] = {
                'success_id': success_id,
                'transaction_id': transaction['transactionId'],
                'amount': amount
            }

            # Redirect to the success page
            return redirect(url_for('payment_success', success_id=success_id))
        else:
            return jsonify({'status': 'error', 'message': 'Insufficient funds'}), 402

    except Exception as e:
        # Handle unexpected errors
        return jsonify({'status': 'error', 'message': 'An error occurred', 'details': str(e)}), 500


@app.route('/payment_success/<success_id>', methods=['GET'])
def payment_success(success_id):
    # Retrieve transaction details from the session
    transaction_details = session.get('transaction_details')
    if not transaction_details or transaction_details.get('success_id') != success_id:
        return redirect(url_for('payment'))  # Redirect to the payment page if no details exist

    # Extract transaction data
    transaction_id = transaction_details.get('transaction_id')
    amount = transaction_details.get('amount')

    # Clear session data to avoid duplication
    session.pop('transaction_details', None)

    return render_template(
        'payment_success.html',
        transaction_id=transaction_id,
        amount=amount
    )

@app.route('/get_account_name', methods=['POST'])
def get_account_name():
    account_number = request.form.get('account_number')
    account = db['accounts'].find_one({'accountNumber': account_number})
    if account:
        customer_id = account['CustomerId']
        customer = db['customers'].find_one({'_id': customer_id})
        if customer['fname']:
            return {'name': customer['fname']}
        elif customer['name']:
            return {'name':customer['name']}
    return {'name': ''}


@app.route('/manage_users')
def manage_users():
    if 'username' in session and session['user_type'] == 'admin':
        username = session['username']
        # Fetch user data from the database
        users = users_collection.find({})
        return render_template('manage_users.html', users=users, username=username)
    else:
        return redirect(url_for('login'))


@app.route('/edit_user/<user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    if 'username' not in session or session['user_type'] != 'admin':
        return redirect(url_for('login'))

    user = users_collection.find_one({'_id': ObjectId(user_id)})
    if not user:
        return 'User not found'

    if request.method == 'POST':
        # Extract data from the form
        updated_fname = request.form.get('fname')
        updated_lname = request.form.get('lname')
        updated_dob = request.form.get('dob')
        updated_address = request.form.get('address')
        updated_contact = request.form.get('contact')
        updated_ssn = request.form.get('ssn')
        updated_username = request.form.get('username')

        # Update user information in the database
        users_collection.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {
                'fname': updated_fname,
                'lname': updated_lname,
                'dob': updated_dob,
                'address': updated_address,
                'contact': updated_contact,
                'ssn': updated_ssn,
                'username': updated_username,
                # Add more fields as needed
            }}
        )

        return redirect(url_for('manage_users'))

    return render_template('edit_user.html', user=user)



@app.route('/delete_user/<user_id>', methods=['GET'])
def delete_user(user_id):
    if 'username' in session and session['user_type'] == 'admin':
        users_collection.delete_one({'_id': ObjectId(user_id)})
        return redirect(url_for('manage_users'))
    else:
        return redirect(url_for('login'))
@app.route('/view_transactions', methods=['GET'])
def view_transactions():
    if 'username' in session and session['user_type'] == 'admin':
        username = session['username']

        # Get filters and sorting preferences from the request
        filter_type = request.args.get('filter_type', 'all')
        sort_order = request.args.get('sort_order', 'desc')

        # Build query based on filter_type
        query = {}
        if filter_type == 'credit':
            query['amount'] = {'$gt': 0}  # Positive amounts for credits
        elif filter_type == 'debit':
            query['amount'] = {'$lt': 0}  # Negative amounts for debits

        # Fetch and sort transactions
        sort_direction = -1 if sort_order == 'desc' else 1
        transactions = db['transactions'].find(query).sort('dateTime', sort_direction)

        # Enhance transactions with additional data
        enhanced_transactions = []
        for transaction in transactions:
            account = db['accounts'].find_one({'accountNumber': transaction['accountId']})
            if account:
                user_id = account['CustomerId']
                user = db['customers'].find_one({'_id': user_id})
                first_name = user.get('fname', 'Unknown')
                last_name = user.get('lname', '')
                user_name = f"{first_name} {last_name}".strip()
            else:
                user_name = 'Unknown'

            if isinstance(transaction['dateTime'], str):
                transaction_datetime = datetime.strptime(transaction['dateTime'], "%Y-%m-%d %H:%M:%S")
            else:
                transaction_datetime = transaction['dateTime']

            formatted_date = transaction_datetime.strftime('%I:%M:%S %p %d-%m-%Y')
            transaction_data = {
                '_id': transaction['_id'],
                'accountId': transaction['accountId'],
                'accountName': user_name,
                'type': transaction['type'],
                'amount': transaction['amount'],
                'formattedDate': formatted_date
            }
            enhanced_transactions.append(transaction_data)

        return render_template(
            'view_transactions.html',
            transactions=enhanced_transactions,
            username=username,
            filter_type=filter_type,
            sort_order=sort_order
        )
    else:
        return redirect(url_for('login'))
@app.route('/add-user', methods=['GET'])
def add_user():
    if 'username' in session:
        username = session['username']
        return render_template('add_user.html', username=username)
    else:
        flash('Please log in to access this functionality.', 'error')
        return redirect(url_for('login'))


@app.route('/create_user', methods=['POST'])
def create_user():
    if 'username' in session and session['user_type'] == 'admin':
        # Collect data from the form
        username = request.form.get('username')
        password = request.form.get('password')
        name = request.form.get('name')
        address = request.form.get('address')
        contact = request.form.get('contact')
        ssn = request.form.get('ssn')
        id_number = request.form.get('id_number')

        # Hash the password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Insert the new Bank Officer into the collection
        bank_officers_collection.insert_one({
            "username": username,
            "password": hashed_password,
            "name": name,
            "address": address,
            "contact": contact,
            "ssn": ssn,
            "id_number": id_number,
            "role": "bankofficer"  # Role is fixed to "bankofficer"
        })

        flash('Bank Officer added successfully', 'success')
        return redirect(url_for('admin_dashboard'))
    else:
        flash('You do not have the permission to create users.', 'error')
        return redirect(url_for('login'))


    @app.route('/apply_overdraft_fee', methods=['POST'])
    def apply_overdraft_fee():
        now = datetime.now()
        overdraft_fee = 35

        overdue_accounts = accounts_collection.find({
            "Enable_Overdraft": True,
            "balance": {"$lt": 0},
            "overdraftStart": {"$exists": True, "$lte": now - timedelta(hours=1)}
        })

        for account in overdue_accounts:
            new_balance = account['balance'] - overdraft_fee
            accounts_collection.update_one(
                {"_id": account["_id"]},
                {"$set": {"balance": new_balance, "overdraftStart": now}}
            )

            transaction = {
                "accountId": account["accountNumber"],
                "amount": -overdraft_fee,
                "type": "Overdraft Fee",
                "dateTime": now.strftime("%Y-%m-%d %H:%M:%S")
            }
            transactions_collection.insert_one(transaction)

        return jsonify({"status": "success", "message": "Overdraft fees applied successfully"})


if __name__ == '__main__':
    app.run(debug=True)
