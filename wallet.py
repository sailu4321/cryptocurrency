from ecdsa import SigningKey, VerifyingKey, SECP256k1, BadSignatureError
import hashlib
from cryptography.fernet import Fernet

class Wallet:
    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.address = None

    def generate_keys(self):
        self.private_key = SigningKey.generate(curve=SECP256k1)
        self.public_key = self.private_key.get_verifying_key()
        self.address = self.public_key_to_address()
        return self.address

    def public_key_to_address(self):
        pubkey_bytes = self.public_key.to_string()
        sha = hashlib.sha256(pubkey_bytes).digest()
        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(sha)
        return ripemd160.hexdigest()

    def sign_transaction(self, sender_address, receiver_address, amount, cryptocurrency_type):
        # Format the amount and crypto type
        formatted_amount = "{:.8f}".format(amount)  # must match backend
        crypto_type = cryptocurrency_type.title()  # "bitcoin" => "Bitcoin"

        # Construct the data string exactly as the backend expects
        transaction_data = f"{sender_address}{receiver_address}{formatted_amount}{crypto_type}"
        print(f"[SIGNING DEBUG] Transaction data string: {transaction_data}")

        # Hash and sign
        tx_hash = hashlib.sha256(transaction_data.encode('utf-8')).digest()
        signature = self.private_key.sign(tx_hash)
        return signature.hex(), transaction_data  # also return data string to verify if needed

    def verify_signature(self, signature_hex, transaction_data, public_key_hex) -> bool:
        try:
            tx_hash = hashlib.sha256(transaction_data.encode()).digest()
            public_key = VerifyingKey.from_string(bytes.fromhex(public_key_hex), curve=SECP256k1)
            return public_key.verify(bytes.fromhex(signature_hex), tx_hash)
        except BadSignatureError:
            return False
        except Exception as e:
            print(f"[DEBUG] Signature verification error: {e}")
            return False
