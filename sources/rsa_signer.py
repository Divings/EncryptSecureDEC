# Copyright (c) 2025 Innovation Craft Inc. All Rights Reserved.
# 本ソフトウェアはプロプライエタリライセンスに基づき提供されています。

import base64
import configparser
import tkinter as tk
from tkinter import messagebox
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import os

def show_info(title, message):
    messagebox.showinfo(title, message)


def show_error(title, message):
    messagebox.showerror(title, message)


import sys

def generate_keys(private_key_path=None, public_key_path=None):
    try:
        # 実行ファイルのディレクトリを基準に Key ディレクトリを構築
        base_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
        key_dir = os.path.join(base_dir, "Key")

        # デフォルトのパス（引数がNoneなら）
        if private_key_path is None:
            private_key_path = os.path.join(key_dir, "private.pem")
        if public_key_path is None:
            public_key_path = os.path.join(key_dir, "public.pem")

        # Keyディレクトリがなければ作成
        if not os.path.exists(key_dir):
            os.makedirs(key_dir)
            show_info("ディレクトリ作成", f"鍵ディレクトリを作成しました：\n{key_dir}")

        if os.path.exists(os.path.join(key_dir, "private.pem")) == False and os.path.exists(os.path.join(key_dir, "public.pem"))==False:
            # 鍵生成
            key = RSA.generate(2048)
            with open(private_key_path, "wb") as f:
                f.write(key.export_key())
            with open(public_key_path, "wb") as f:
                f.write(key.publickey().export_key())

            show_info("鍵生成", f"🔐 鍵ペアを生成しました。\n\n秘密鍵: {private_key_path}\n公開鍵: {public_key_path}")
    except Exception as e:
        show_error("エラー", f"鍵生成中にエラーが発生しました。\n{e}")



def get_signature_filename(file_path: str) -> str:
    return file_path + ".sig"


import sys

def sign_file(file_path: str, private_key_path: str = None):
    try:
        # デフォルトの鍵パスを sys.argv[0] 基準で設定
        if private_key_path is None:
            base_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
            private_key_path = os.path.join(base_dir, "Key", "private.pem")

        signature_path = get_signature_filename(file_path)

        with open(private_key_path, "rb") as f:
            private_key = RSA.import_key(f.read())

        with open(file_path, "rb") as f:
            file_data = f.read()

        hash_obj = SHA256.new(file_data)
        signature = pkcs1_15.new(private_key).sign(hash_obj)

        with open(signature_path, "wb") as f:
            f.write(base64.b64encode(signature))

        show_info("署名成功", f"✅ 署名を保存しました。\n\nファイル: {signature_path}")
    except Exception as e:
        show_error("署名エラー", f"署名作成中にエラーが発生しました。\n{e}")


def verify_file_signature(file_path: str, public_key_path: str = None):
    try:
        # デフォルトの鍵パスを sys.argv[0] 基準で設定
        if public_key_path is None:
            base_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
            public_key_path = os.path.join(base_dir, "Key", "public.pem")

        signature_path = get_signature_filename(file_path)

        with open(public_key_path, "rb") as f:
            public_key = RSA.import_key(f.read())

        with open(file_path, "rb") as f:
            file_data = f.read()
        with open(signature_path, "rb") as f:
            signature_b64 = f.read()

        try:
            signature = base64.b64decode(signature_b64)
        except Exception:
            show_error("署名エラー", "Base64デコード失敗：署名ファイルが破損しています。")
            return

        hash_obj = SHA256.new(file_data)

        pkcs1_15.new(public_key).verify(hash_obj, signature)
        show_info("検証成功", "検証成功：署名とファイルは一致しています。")
        return 1
    except (ValueError, TypeError):
        show_error("検証失敗", "署名が改ざんされているか、ファイルが変更されています。")
    except Exception as e:
        show_error("検証エラー", f"検証中にエラーが発生しました。\n{e}")

