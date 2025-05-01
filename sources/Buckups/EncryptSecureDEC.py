# Copyright (c) 2025 Innovation Craft Inc. All Rights Reserved.
# 本ソフトウェアはプロプライエタリライセンスに基づき提供されています。

import os
import json
import hashlib
import datetime
import getpass
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import lzma
import rsa_signer
rsa_signer.generate_keys()
import master_password_manager
import sys

if __name__ == "__main__":
    password = master_password_manager.login_gui()
    if password == -1:
        sys.exit(-1)  # ❎ ユーザーがクローズボタンを押した場合 → 静かに終了
    if password is None:
        messagebox.showerror("認証失敗", "認証に失敗したためアプリケーションを終了します。")
        sys.exit(-1)
    
BLOCKCHAIN_HEADER = b'BLOCKCHAIN_DATA_START\n'

class Block:
    def __init__(self, data, previous_hash, operation_type, file_hash, user, memo):
        self.timestamp = datetime.datetime.now(datetime.timezone.utc)
        self.data = data
        self.previous_hash = previous_hash
        self.operation_type = operation_type
        self.file_hash = file_hash
        self.user = user
        self.memo = memo
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        sha = hashlib.sha256()
        sha.update(
            str(self.timestamp).encode('utf-8') +
            str(self.data).encode('utf-8') +
            str(self.previous_hash).encode('utf-8') +
            str(self.operation_type).encode('utf-8') +
            str(self.file_hash).encode('utf-8') +
            str(self.user).encode('utf-8') +
            str(self.memo).encode('utf-8')
        )
        return sha.hexdigest()

    def to_dict(self):
        return {
            'timestamp': str(self.timestamp),
            'data': self.data,
            'previous_hash': self.previous_hash,
            'operation_type': self.operation_type,
            'file_hash': self.file_hash,
            'user': self.user,
            'memo': self.memo,
            'hash': self.hash
        }

class Blockchain:
    def __init__(self):
        self.chain = []

    def add_block(self, new_block):
        if len(self.chain) == 0:
            new_block.previous_hash = "0"
        else:
            new_block.previous_hash = self.chain[-1].hash
        new_block.hash = new_block.calculate_hash()
        self.chain.append(new_block)

    def to_json(self):
        return json.dumps([block.to_dict() for block in self.chain], indent=2)

    @staticmethod
    def from_json(data):
        chain_data = json.loads(data)
        blockchain = Blockchain()
        for block_data in chain_data:
            block = Block(
                data=block_data['data'],
                previous_hash=block_data['previous_hash'],
                operation_type=block_data['operation_type'],
                file_hash=block_data['file_hash'],
                user=block_data['user'],
                memo=block_data['memo']
            )
            block.timestamp = datetime.datetime.strptime(block_data['timestamp'], '%Y-%m-%d %H:%M:%S.%f%z')
            block.hash = block_data['hash']
            blockchain.chain.append(block)
        return blockchain

    def is_chain_valid(self):
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]
            if current.previous_hash != previous.hash:
                return False
            if current.calculate_hash() != current.hash:
                return False
        return True

def encrypt():
    file_path = filedialog.askopenfilename(title="暗号化するファイルを選択")
    if not file_path:
        return
    password = password_entry.get()
    memo = memo_entry.get()
    with open(file_path, 'rb') as f:
        plaintext = f.read()

    salt = get_random_bytes(16)
    key = PBKDF2(password, salt, dkLen=32, count=100_000)
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    encrypted_path = file_path + ".vdec"
    file_hash = hashlib.sha256(ciphertext).hexdigest()
    username = getpass.getuser()

    try:
        with lzma.open(encrypted_path, 'rb') as f:
            data = f.read()
        split_index = data.index(BLOCKCHAIN_HEADER)
        chain_json = data[split_index + len(BLOCKCHAIN_HEADER):].decode('utf-8')
        blockchain = Blockchain.from_json(chain_json)
    except:
        blockchain = Blockchain()

    block = Block(file_hash, blockchain.chain[-1].hash if blockchain.chain else "0", "Encrypt", file_hash, username, memo)
    blockchain.add_block(block)

    with lzma.open(encrypted_path, 'wb') as f:
        f.write(salt + nonce + ciphertext + tag)
        f.write(BLOCKCHAIN_HEADER)
        f.write(blockchain.to_json().encode('utf-8'))

    messagebox.showinfo("完了", f"暗号化完了:\n{encrypted_path}")

def decrypt():
    encrypted_path = filedialog.askopenfilename(title="復号化する.vdecファイルを選択", filetypes=[("Encrypted Files", "*.vdec")])
    if not encrypted_path:
        return
    password = password_entry.get()
    memo = memo_entry.get()

    with lzma.open(encrypted_path, 'rb') as f:
        data = f.read()

    try:
        split_index = data.index(BLOCKCHAIN_HEADER)
        crypto_data = data[:split_index]
        chain_json = data[split_index + len(BLOCKCHAIN_HEADER):].decode('utf-8')
        blockchain = Blockchain.from_json(chain_json)

        salt = crypto_data[:16]
        nonce = crypto_data[16:28]
        tag = crypto_data[-16:]
        ciphertext = crypto_data[28:-16]
    except Exception:
        messagebox.showerror("エラー", "ファイル形式が不正です")
        return

    key = PBKDF2(password, salt, dkLen=32, count=100_000)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        messagebox.showerror("エラー", "復号失敗：パスワードが間違っているか、ファイルが改ざんされています。")
        return

    output_file = encrypted_path.replace(".vdec", "_decrypted")
    with open(output_file, 'wb') as f:
        f.write(plaintext)

    username = getpass.getuser()
    file_hash = hashlib.sha256(ciphertext).hexdigest()
    block = Block(file_hash, blockchain.chain[-1].hash if blockchain.chain else "0", "Decrypt", file_hash, username, memo)
    blockchain.add_block(block)

    with lzma.open(encrypted_path, 'wb') as f:
        f.write(salt + nonce + ciphertext + tag)
        f.write(BLOCKCHAIN_HEADER)
        f.write(blockchain.to_json().encode('utf-8'))

    messagebox.showinfo("完了", f"復号化完了:\n{output_file}")

def verify_blockchain():
    encrypted_path = filedialog.askopenfilename(title="確認する.vdecファイルを選択", filetypes=[("Encrypted Files", "*.vdec")])
    if not encrypted_path:
        return
    with lzma.open(encrypted_path, 'rb') as f:
        data = f.read()
    try:
        split_index = data.index(BLOCKCHAIN_HEADER)
        chain_json = data[split_index + len(BLOCKCHAIN_HEADER):].decode('utf-8')
        blockchain = Blockchain.from_json(chain_json)
    except Exception:
        messagebox.showerror("エラー", "ブロックチェーンデータの読み込みに失敗しました")
        return

    if blockchain.is_chain_valid():
        messagebox.showinfo("確認", "ブロックチェーンは整合しています。")
    else:
        messagebox.showerror("エラー", "ブロックチェーンに不整合があります。")

def sign_current_file():
    file_path = filedialog.askopenfilename(title="署名するファイルを選択してください")
    if file_path:
        try:
            rsa_signer.sign_file(file_path)
        except Exception as e:
            messagebox.showerror("署名エラー", str(e))

# ✅ 署名検証処理：ファイル選択して署名確認
def verify_current_file_signature():
    file_path = filedialog.askopenfilename(title="署名を検証するファイルを選択してください")
    if file_path:
        try:
            rsa_signer.verify_file_signature(file_path)
        
        except Exception as e:
            messagebox.showerror("検証エラー", str(e))


# GUI構築
window = tk.Tk()
window.geometry("480x300")
window.title("Encrypt Secure DEC - (C) Innovation Craft")
window.configure(bg='#E0F2F1')
window.resizable(False, False)

try:
    window.iconbitmap('resources/IMG_8776.ICO')
except:
    pass

password_label = ttk.Label(window, text="パスワード：", background='#E0F2F1')
password_label.place(x=20, y=30)
password_entry = tk.Entry(window, show='*', font=('', 14))
password_entry.place(x=130, y=30, width=300)

memo_label = ttk.Label(window, text="メモ：", background='#E0F2F1')
memo_label.place(x=20, y=70)
memo_entry = tk.Entry(window, font=('', 14))
memo_entry.place(x=130, y=70, width=300)

encrypt_button = tk.Button(window, text="暗号化", command=encrypt, font=('', 14), width=10)
encrypt_button.place(x=80, y=120)

decrypt_button = tk.Button(window, text="復号化", command=decrypt, font=('', 14), width=10)
decrypt_button.place(x=200, y=120)

verify_button = tk.Button(window, text="ブロックチェーンの整合性確認", command=verify_blockchain, font=('', 14), width=30)
verify_button.place(x=80, y=180)

# 署名ボタン（例: x=80, y=220）
sign_button = tk.Button(window, text="署名する", command=sign_current_file, font=('', 14), width=10)
sign_button.place(x=80, y=220)

# 署名検証ボタン（例: x=200, y=220）
verify_sig_button = tk.Button(window, text="署名検証", command=verify_current_file_signature, font=('', 14), width=10)
verify_sig_button.place(x=200, y=220)


footer = ttk.Label(window, text='(C) Innovation Craft', background='#E0F2F1')
footer.place(x=5, y=270)

window.mainloop()
