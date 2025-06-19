from flask_sqlalchemy import SQLAlchemy
from app import db
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import UniqueConstraint, ForeignKey

class Wallet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    private_key = db.Column(db.String(256), nullable=False)
    public_key = db.Column(db.String(256), nullable=False)
    address = db.Column(db.String(64), unique=True, nullable=False)
    encrypted_key = db.Column(db.String(256))
    encryption_key = db.Column(db.String(256))
    bitcoin_balance = db.Column(db.Float, default=0)
    ethereum_balance = db.Column(db.Float, default=0)
    litecoin_balance = db.Column(db.Float, default=0)
    ripple_balance = db.Column(db.Float, default=0)

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_username = db.Column(db.String(80), nullable=False, index=True)
    receiver_username = db.Column(db.String(80), nullable=False, index=True)
    sender_address = db.Column(db.String(64), nullable=False, index=True)
    receiver_address = db.Column(db.String(64), nullable=False, index=True)
    amount = db.Column(db.Float, nullable=False)
    cryptocurrency_type = db.Column(db.String(50), nullable=False)
    signature = db.Column(db.String(256), nullable=False)
    public_key = db.Column(db.String(256), nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp(), index=True)

class Balance(db.Model):
    __tablename__ = 'balance'

    id = db.Column(db.Integer, primary_key=True)
    wallet_address = db.Column(
        db.String(64),
        db.ForeignKey('wallet.address', name='fk_balance_wallet_address'),
        nullable=False,
        index=True
    )
    cryptocurrency_type = db.Column(db.String(50), nullable=False, index=True)
    amount = db.Column(db.Float, default=0.0)

    __table_args__ = (
        UniqueConstraint('wallet_address', 'cryptocurrency_type', name='uix_balance_wallet_crypto'),
    )
