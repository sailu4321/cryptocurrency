from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from app import db
from app.models import Wallet, Transaction
from app.wallet import Wallet as CryptoWallet
from app.blockchain import MockBlockchain
from werkzeug.security import generate_password_hash, check_password_hash
import qrcode
from io import BytesIO
import base64
import requests
from ecdsa import SigningKey, SECP256k1

main = Blueprint('main', __name__)
blockchain = MockBlockchain()

@main.route('/')
def home():
    return render_template('home.html')

@main.route('/create_wallet', methods=['GET', 'POST'])
def create_wallet():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if Wallet.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
            return redirect(url_for('main.create_wallet'))

        crypto_wallet = CryptoWallet()
        address = crypto_wallet.generate_keys()
        password_hash = generate_password_hash(password)

        initial_balances = {
            'Bitcoin': 100,
            'Ethereum': 50,
            'Litecoin': 200,
            'Ripple': 500
        }

        new_wallet = Wallet(
            username=username,
            password_hash=password_hash,
            private_key=crypto_wallet.private_key.to_string().hex(),
            public_key=crypto_wallet.public_key.to_string().hex(),
            address=address,
            bitcoin_balance=initial_balances['Bitcoin'],
            ethereum_balance=initial_balances['Ethereum'],
            litecoin_balance=initial_balances['Litecoin'],
            ripple_balance=initial_balances['Ripple']
        )

        db.session.add(new_wallet)
        db.session.commit()

        for coin, amount in initial_balances.items():
            blockchain.set_balance(address, coin, amount)

        session['wallet_id'] = new_wallet.id
        flash('Wallet created successfully!', 'success')
        return redirect(url_for('main.dashboard'))

    return render_template('create_wallet.html')

@main.route('/load_wallet', methods=['GET', 'POST'])
def load_wallet():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        wallet = Wallet.query.filter_by(username=username).first()
        if wallet and check_password_hash(wallet.password_hash, password):
            session['wallet_id'] = wallet.id
            flash('Wallet loaded successfully!', 'success')
            return redirect(url_for('main.dashboard'))

        flash('Invalid username or password.', 'danger')
    return render_template('load_wallet.html')

@main.route('/dashboard')
def dashboard():
    wallet_id = session.get('wallet_id')
    if not wallet_id:
        return redirect(url_for('main.home'))

    wallet = Wallet.query.get(wallet_id)
    coins = ['Bitcoin', 'Ethereum', 'Litecoin', 'Ripple']

    balances = {
        coin: blockchain.get_balance(wallet.address, coin)
        for coin in coins
    }

    try:
        response = requests.get(
            'https://api.coingecko.com/api/v3/simple/price',
            params={'ids': 'bitcoin,ethereum,litecoin,ripple', 'vs_currencies': 'usd'}
        )
        prices_json = response.json()
        prices = {
            'Bitcoin': prices_json.get('bitcoin', {}).get('usd', 'N/A'),
            'Ethereum': prices_json.get('ethereum', {}).get('usd', 'N/A'),
            'Litecoin': prices_json.get('litecoin', {}).get('usd', 'N/A'),
            'Ripple': prices_json.get('ripple', {}).get('usd', 'N/A')
        }
    except Exception as e:
        print("Price fetch error:", e)
        prices = {coin: 'N/A' for coin in coins}

    return render_template(
        'dashboard.html',
        wallet=wallet,
        balances=balances,
        prices=prices
    )

@main.route('/send_transaction', methods=['GET', 'POST'])
def send_transaction():
    wallet_id = session.get('wallet_id')
    if not wallet_id:
        return redirect(url_for('main.home'))

    wallet = Wallet.query.get(wallet_id)

    if request.method == 'POST':
        receiver_username = request.form.get('receiver_username')
        receiver_address = request.form.get('receiver_address')
        amount = float(request.form.get('amount'))
        cryptocurrency_type = request.form.get('cryptocurrency_type')

        receiver_wallet = Wallet.query.filter_by(username=receiver_username).first()
        if not receiver_wallet:
            flash('Receiver wallet not found!', 'danger')
            return redirect(url_for('main.send_transaction'))

        crypto_wallet = CryptoWallet()
        crypto_wallet.private_key = SigningKey.from_string(bytes.fromhex(wallet.private_key), curve=SECP256k1)
        crypto_wallet.public_key = crypto_wallet.private_key.get_verifying_key()
        crypto_wallet.address = wallet.address

        sender_address = crypto_wallet.address
        receiver_address = receiver_wallet.address

        signature, transaction_data = crypto_wallet.sign_transaction(
            sender_address,
            receiver_address,
            amount,
            cryptocurrency_type
        )

        success, message = blockchain.send_transaction(
            sender_address,
            receiver_address,
            amount,
            signature,
            crypto_wallet.public_key.to_string().hex(),
            wallet.username,
            receiver_wallet.username,
            cryptocurrency_type
        )

        if success:
            db.session.commit()
            flash(message, 'success')
            return redirect(url_for('main.dashboard'))
        else:
            flash(message, 'danger')

    return render_template('send_transaction.html', wallet=wallet)

@main.route('/profile')
def profile():
    wallet_id = session.get('wallet_id')
    if not wallet_id:
        return redirect(url_for('main.home'))

    wallet = Wallet.query.get(wallet_id)
    coins = ['Bitcoin', 'Ethereum', 'Litecoin', 'Ripple']
    balances = {
        coin: blockchain.get_balance(wallet.address, coin)
        for coin in coins
    }

    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(f"Username: {wallet.username}\nWallet Address: {wallet.address}")
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    buffered = BytesIO()
    img.save(buffered)
    qr_code = base64.b64encode(buffered.getvalue()).decode('utf-8')

    return render_template('profile.html', wallet=wallet, qr_code=qr_code, balances=balances)

@main.route('/transaction_history')
def transaction_history():
    wallet_id = session.get('wallet_id')
    if not wallet_id:
        flash("Please log in to view transaction history.", "warning")
        return redirect(url_for('main.load_wallet'))

    wallet = Wallet.query.get(wallet_id)
    if not wallet:
        flash("Wallet not found.", "danger")
        return redirect(url_for('main.load_wallet'))

    sent_transactions = Transaction.query.filter_by(sender_address=wallet.address).order_by(Transaction.timestamp.desc()).all()
    received_transactions = Transaction.query.filter_by(receiver_address=wallet.address).order_by(Transaction.timestamp.desc()).all()

    return render_template(
        'transaction_history.html',
        wallet=wallet,
        sent_transactions=sent_transactions,
        received_transactions=received_transactions
    )
