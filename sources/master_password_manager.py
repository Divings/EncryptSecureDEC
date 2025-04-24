# Copyright (c) 2025 Innovation Craft Inc. All Rights Reserved.
# 本ソフトウェアはプロプライエタリライセンスに基づき提供されています。

import os
import sqlite3
from Crypto.Protocol.KDF import PBKDF2
import tkinter as tk
from tkinter import messagebox

DB_PATH = "userdata.db"

def _init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS master_password (
            id INTEGER PRIMARY KEY,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def set_master_password(password: str):
    _init_db()
    salt = os.urandom(16)
    hash_pw = PBKDF2(password, salt, dkLen=32, count=100_000)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM master_password")
    c.execute("INSERT INTO master_password (password_hash, salt) VALUES (?, ?)",
              (hash_pw.hex(), salt.hex()))
    conn.commit()
    conn.close()

def verify_master_password(input_password: str) -> bool:
    _init_db()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT password_hash, salt FROM master_password")
    row = c.fetchone()
    conn.close()
    if not row:
        return False
    stored_hash = bytes.fromhex(row[0])
    salt = bytes.fromhex(row[1])
    test_hash = PBKDF2(input_password, salt, dkLen=32, count=100_000)
    return stored_hash == test_hash

def is_password_set() -> bool:
    _init_db()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM master_password")
    count = c.fetchone()[0]
    conn.close()
    return count > 0

# ✅ GUIログイン画面（認証成功でパスワード返却）
def login_gui() -> str | int:
    result_password = {"value": None}
    attempts = {"count": 0}

    def try_login():
        pw = entry.get()
        if not pw:
            messagebox.showerror("エラー", "パスワードを入力してください。")
            return
        if is_password_set():
            if verify_master_password(pw):
                result_password["value"] = pw
                login.destroy()
            else:
                attempts["count"] += 1
                if attempts["count"] >= 3:
                    messagebox.showerror("認証失敗", "3回連続で失敗しました。終了します。")
                    login.destroy()
                else:
                    messagebox.showerror("エラー", f"マスターパスワードが間違っています（{attempts['count']}回目）")
        else:
            if messagebox.askyesno("初期設定", "マスターパスワードを新規設定しますか？"):
                set_master_password(pw)
                messagebox.showinfo("設定完了", "マスターパスワードを保存しました。")
                result_password["value"] = pw
                login.destroy()

    def on_close():
        result_password["value"] = -1
        login.destroy()

    login = tk.Tk()
    login.title("マスターパスワード認証")
    login.geometry("400x200")
    login.configure(bg='#E0F2F1')
    login.resizable(False, False)
    try:
        login.iconbitmap('resources/IMG_8776.ICO')
    except:
        pass

    login.protocol("WM_DELETE_WINDOW", on_close)  # ❎ クローズイベントハンドラ

    tk.Label(login, text="マスターパスワード：", bg='#E0F2F1', font=('', 14)).place(x=20, y=50)
    entry = tk.Entry(login, show="*", font=('', 14))
    entry.place(x=180, y=50, width=180)

    tk.Button(login, text="ログイン", command=try_login, font=('', 14)).place(x=150, y=110, width=100)

    login.mainloop()
    return result_password["value"]
