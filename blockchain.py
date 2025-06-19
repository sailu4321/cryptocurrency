from app import db
from app.models import Transaction, Balance
from ecdsa import VerifyingKey, SECP256k1, BadSignatureError
import binascii
import hashlib

class MockBlockchain:
    def get_balance(self, address, cryptocurrency_type):
        cryptocurrency_type = cryptocurrency_type.title()
        balance = Balance.query.filter_by(wallet_address=address, cryptocurrency_type=cryptocurrency_type).first()
        return balance.amount if balance else 0.0

    def set_balance(self, address, cryptocurrency_type, amount):
        cryptocurrency_type = cryptocurrency_type.title()
        amount = max(0.0, amount)
        balance = Balance.query.filter_by(wallet_address=address, cryptocurrency_type=cryptocurrency_type).first()
        if balance:
            balance.amount = amount
        else:
            balance = Balance(wallet_address=address, cryptocurrency_type=cryptocurrency_type, amount=amount)
            db.session.add(balance)
        db.session.commit()

    def send_transaction(self, sender_address, receiver_address, amount, signature, public_key_hex, sender_username, receiver_username, cryptocurrency_type):
        # ✅ STEP 1: Format and prepare transaction data
        cryptocurrency_type = cryptocurrency_type.title()
        formatted_amount = "{:.8f}".format(amount)
        transaction_data = f"{sender_address}{receiver_address}{formatted_amount}{cryptocurrency_type}"
        print(f"[DEBUG] Transaction Data for Verification: {transaction_data}")

        # ✅ STEP 2: Reconstruct verifying key from public key
        try:
            verifying_key = VerifyingKey.from_string(bytes.fromhex(public_key_hex), curve=SECP256k1)
        except Exception as e:
            print(f"[DEBUG] Error reconstructing public key: {e}")
            return False, "Invalid public key format"

        # ✅ STEP 3: Verify the signature with SHA-256 hash of transaction data
        try:
            signature_bytes = binascii.unhexlify(signature)
            tx_hash = hashlib.sha256(transaction_data.encode('utf-8')).digest()
            verifying_key.verify(signature_bytes, tx_hash)
        except BadSignatureError:
            print("[DEBUG] BadSignatureError: Signature does not match")
            return False, "Invalid signature"
        except Exception as e:
            print(f"[DEBUG] Signature verification failed: {e}")
            return False, "Invalid signature"

        # ✅ STEP 4: Check sender balance and proceed if sufficient
        sender_balance = self.get_balance(sender_address, cryptocurrency_type)
        if sender_balance < amount:
            return False, "Insufficient balance"

        # ✅ STEP 5: Update balances
        self.set_balance(sender_address, cryptocurrency_type, sender_balance - amount)
        receiver_balance = self.get_balance(receiver_address, cryptocurrency_type)
        self.set_balance(receiver_address, cryptocurrency_type, receiver_balance + amount)

        # ✅ STEP 6: Log the transaction in DB
        tx = Transaction(
            sender_username=sender_username,
            receiver_username=receiver_username,
            sender_address=sender_address,
            receiver_address=receiver_address,
            amount=amount,
            cryptocurrency_type=cryptocurrency_type,
            signature=signature,
            public_key=public_key_hex
        )
        db.session.add(tx)
        db.session.commit()

        return True, "Transaction successful"
