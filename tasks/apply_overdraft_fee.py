from datetime import datetime, timedelta
from pymongo import MongoClient

# MongoDB configuration
client = MongoClient('mongodb://localhost:27017/')
db = client['adb']
accounts_collection = db['accounts']
transactions_collection = db['transactions']

def apply_overdraft_fee():
    now = datetime.now()
    overdraft_fee = 35

    # Use the query to find overdue accounts
    overdue_accounts = accounts_collection.find({
        "Enable_Overdraft": True,
        "balance": {"$lt": 0},
        "overdraftStart": {"$exists": True, "$lte": now - timedelta(hours=24)}
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
        print(f"Overdraft fee applied to account {account['accountNumber']}")

if __name__ == "__main__":
    apply_overdraft_fee()
