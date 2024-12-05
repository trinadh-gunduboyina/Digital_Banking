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

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Collect data from the form
        fname = request.form.get('fname')
        lname = request.form.get('lname')
        dob = request.form.get('dob')
        address = request.form.get('address')
        contact = request.form.get('contact')
        ssn = request.form.get('ssn')
        username = request.form.get('username')
        password = request.form.get('password')
        cpassword = request.form.get('cpassword')
        bank_id = request.form.get('bank_id')

        # Validate required fields
        if not all([fname, lname, dob, address, contact, ssn, username, password, cpassword, bank_id]):
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

        # Enforce strong password policy (example: minimum 8 characters)
        if len(password) < 8:
            flash('Password must be at least 8 characters long', 'error')
            return redirect(url_for('register'))

        # Check for duplicate username
        existing_user = db.users.find_one({"username": username})
        if existing_user:
            flash('Username already exists', 'error')
            return redirect(url_for('register'))

        # Hash the password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Create user object
        user = {
            "fname": fname,
            "lname": lname,
            "dob": dob,
            "address": address,
            "contact": contact,
            "ssn": ssn,  # Encrypt or mask before saving
            "username": username,
            "password": hashed_password,
            "bank_id": bank_id,
            "isActive": False  # Set account activation logic
        }

#########   Account number functionality ############
        user_inserted = users_collection.insert_one(user)

        # Generate a 12-digit numeric account number
        account_number = ''.join([str(random.randint(0, 9)) for _ in range(12)])

        # Generate a 16-digit numeric debit card number
        debit_card_number = ''.join([str(random.randint(0, 9)) for _ in range(16)])

        # Create an account for the user
        account = {
            "accountNumber": account_number,
            "CustomerId": user_inserted.inserted_id,  # MongoDB generated ID
            "balance": 0,
            "debitCard": debit_card_number,
            "bankId": ObjectId(bank_id),
            "Enable_Overdraft": False,
            "overdraftStart" : None

        }

        # Insert the account into the 'accounts' collection
        db['accounts'].insert_one(account)

        flash('Registration successful', 'success')
        return redirect(url_for('login'))

    banks = list(db['banks'].find({}))
    return render_template('register.html',banks=banks)



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

        if request.method == 'POST':
            category_id = request.form.get('account_type')
            enable_overdraft = request.form.get('enable_overdraft') == 'on'  # Checkbox for overdraft
            # Update user and account details in the database
            users_collection.update_one(
                {'_id': ObjectId(user_id)},
                {'$set': {'isActive': True, 'accountTypeId': ObjectId(category_id),
                          'Enable_Overdraft': enable_overdraft}}
            )

            #Overdraft enabled functionality
            if enable_overdraft:
                accounts_collection.update_one({'CustomerId':user.get('_id')},
                                               {'$set': {'Enable_Overdraft': True}})

            # Redirect to the approval page
            return redirect(url_for('approve_users'))

            # Fetch account types and bank information for the approval form
        categories = db['category'].find()
        account_types = [{'id': str(category['_id']), 'type': category['AccountType']} for category in categories]
        account = accounts_collection.find_one({'CustomerId': ObjectId(user_id)})
        bank = banks_collection.find_one({'_id': ObjectId(account['bankId'])})

        return render_template('approve_user.html', user=user, account_types=account_types, username=username,
                               bank=bank)
    else:
        return redirect(url_for('login'))

@app.route('/deposit_money', methods=['GET', 'POST'])
def deposit_money():
    if 'username' in session and session['user_type'] == 'admin':
        username=session['username']
        if request.method == 'POST':
            account_number = request.form.get('account_number')
            deposit_amount = float(request.form.get('deposit_amount'))

            # Fetch the account and update the balance
            account = db['accounts'].find_one({'accountNumber': account_number})
            if account:
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
                flash('Account not found', 'error')

            return redirect(url_for('deposit_money'))

        return render_template('deposit_money.html',username=username)
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

            # Attach bank details to each account
            for account in accounts:
                bank = banks_collection.find_one({'_id': account['bankId']})
                account['bankName'] = bank['name'] if bank else 'Unknown Bank'

                # Fetch and format transactions for each account
                transactions = list(transactions_collection.find({
                    '$or': [
                        {'accountId': account["accountNumber"]},  # Credit transactions
                        {'receiverAccount': account["accountNumber"]}  # Debit transactions
                    ]
                }).sort('dateTime', -1))
                last_transaction = transactions[0] if transactions else None

                for transaction in transactions:
                    if isinstance(transaction['dateTime'], str):
                        transaction_datetime = datetime.strptime(transaction['dateTime'], "%Y-%m-%d %H:%M:%S")
                    else:
                        transaction_datetime = transaction['dateTime']

                    print(transaction)
                    # Format dateTime to 12-hour format
                    transaction['dateTime'] = transaction_datetime.strftime('%I:%M %p %d-%m-%Y')



                account['transactions'] = transactions
                account['lastTransaction'] = transactions[0] if transactions else None
                account_type = "Not Available"  # Default if not found
                if 'accountTypeId' in user:
                    category = db['category'].find_one({'_id': user['accountTypeId']})
                    account_type = category['AccountType'] if category else account_type

                if account:
                    account_details = {
                        'fname': user['fname'],
                        'lname': user['lname'],
                        'balance': account['balance'],
                        'debitCardNumber': account['debitCard'],
                        'accountNumber': account['accountNumber'],
                        'address': user['address'],
                        'ssn': user['ssn'],
                        'accountType': account_type
                    }

            return render_template('dashboard.html', username=username, accounts=accounts, account_details=account_details, transactions=transactions, last_transaction=last_transaction)

        else:
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
        total_users = users_collection.count_documents({})
        bank_officers = bank_officers_collection.count_documents({})
        total_transactions = transactions_collection.count_documents({})

        return render_template('admin_dashboard.html',
                               username=session['username'],
                               total_users=total_users,
                               bank_officers=bank_officers,
                               total_transactions=total_transactions)
    else:
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
        amount = float(request.form.get('amount'))

        # Validate input
        if not debit_card_number or amount <= 0:
            return jsonify({'status': 'error', 'message': 'Invalid debit card number or amount'}), 400

        # Fetch the account by debit card number
        account = db['accounts'].find_one({'debitCard': debit_card_number})

        if not account:
            return jsonify({'status': 'error', 'message': 'Invalid debit card number'}), 404

        # Check balance and overdraft status
        balance = account.get('balance', 0.0)
        overdraft_enabled = account.get('Enable_Overdraft', False)
        available_funds = balance

        # Overdraft amount
        overdraft_limit = account.get('overdraftLimit', 1000) if overdraft_enabled else 0
        available_funds += overdraft_limit

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


@app.route('/view_transactions')
def view_transactions():
    if 'username' in session and session['user_type'] == 'admin':
        username = session['username']
        transactions = db['transactions'].find({}).sort('dateTime', -1)

        # Enhance transactions with user name and separate credit/debit
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

            # Convert dateTime to a datetime object if it's not already
            if isinstance(transaction['dateTime'], str):
                transaction_datetime = datetime.strptime(transaction['dateTime'], "%Y-%m-%d %H:%M:%S")
            else:
                transaction_datetime = transaction['dateTime']

            # Format dateTime to 12-hour format
            formatted_date = transaction_datetime.strftime('%I:%M %p %d-%m-%Y')

            transaction_data = {
                '_id': transaction['_id'],
                'accountId': transaction['accountId'],
                'accountName': user_name,  # Add user name
                'type': transaction['type'],
                'amount': transaction['amount'],
                'formattedDate': formatted_date  # Use formatted date
            }
            enhanced_transactions.append(transaction_data)

        return render_template('view_transactions.html', transactions=enhanced_transactions, username=username)
    else:
        return redirect(url_for('login'))



@app.route('/add-user', methods=['GET'])
def add_user():
    if 'username' in session and session['user_type'] == 'admin':
        username = session['username']
        return render_template('add_user.html', username=username)
    else:
        return redirect(url_for('login'))


@app.route('/create-user', methods=['POST'])
def create_user():
    if 'username' in session and session['user_type'] == 'admin':
        username = request.form['username']
        name = request.form.get('name')  # Add a name field in your form for bank officers
        password = request.form['password']
        role = request.form['role']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        if role == 'bankofficer':
            bank_officers_collection.insert_one({
                "name": name,
                "username": username,
                "password": hashed_password,
                "deposit": True  # Assuming all bank officers have deposit rights
            })
        elif role == 'admin':
            admin_users_collection.insert_one({
                "username": username,
                "password": hashed_password
            })

        return redirect(url_for('admin_dashboard'))
    else:
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
