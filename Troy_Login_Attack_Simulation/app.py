from datetime import datetime
import os
from pathlib import Path
from flask import Flask, render_template, request

APP_DIR = Path(__file__).resolve().parent
LOG_FILE = Path(r'C:\Users\defense\Desktop\4309_FinalProject\Troy_Login_Attack_Simulation\auth.log')

VALID_USERNAME = os.environ.get('CPPBANK_USERNAME', 'bankuser')
VALID_PASSWORD = os.environ.get('CPPBANK_PASSWORD', 'SecurePass123')

app = Flask(__name__)


def clean_log_value(value):
    return str(value).replace('|', '/').replace('\r', ' ').replace('\n', ' ').strip()


def get_client_ip():
    if os.environ.get('CPPBANK_TRUST_PROXY') == '1':
        forwarded_for = request.headers.get('X-Forwarded-For', '')
        if forwarded_for:
            return clean_log_value(forwarded_for.split(',')[0])
    return clean_log_value(request.remote_addr or 'unknown')


def write_log(username, ip, status, reason):
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_entry = (
        f'{timestamp} defense-vm IP={clean_log_value(ip)} | USER={clean_log_value(username)} | '
        f'STATUS={clean_log_value(status)} | REASON={clean_log_value(reason)}\n'
    )
    with LOG_FILE.open('a', encoding='utf-8') as file:
        file.write(log_entry)


@app.get('/healthz')
def healthz():
    return {'status': 'ok'}


@app.route('/', methods=['GET', 'POST'])
def login():
    message = ''
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        ip = get_client_ip()
        if username == VALID_USERNAME and password == VALID_PASSWORD:
            write_log(username, ip, 'SUCCESS', 'Valid login')
            message = 'Login successful. Welcome to CPP Bank.'
        else:
            write_log(username, ip, 'FAILED', 'Invalid username or password')
            message = 'Login failed. Invalid username or password.'
    return render_template('login.html', message=message)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
