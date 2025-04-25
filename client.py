import socket
import threading
import base64
import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# تابع تولید کلید مشتق‌شده از گذرواژه (SHA256)
def derive_key(password):
    return hashlib.sha256(password.encode()).digest()

# رمزگذاری با AES-CBC؛ IV تصادفی در ابتدا
def encrypt_data(key, data):
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(data.encode(), AES.block_size))
    return base64.b64encode(iv + encrypted).decode()

# رمزگشایی با AES-CBC
def decrypt_data(key, encrypted_data):
    try:
        raw = base64.b64decode(encrypted_data)
        iv, encrypted = raw[:16], raw[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(encrypted), AES.block_size).decode()
    except Exception as e:
        print(f"⚠️ Error decrypting data: {e}")
        return "Decryption failed"

# دریافت پیام‌ها از سرور
def receive_messages(client, chat_key):
    while True:
        try:
            message = client.recv(4096).decode()
            if message.startswith("Private message"):
                # انتظار فرمت:
                # Private message, length=<len> from <sender> to <recipient>:
                # <encrypted_message>
                parts = message.split(":\n", 1)
                if len(parts) > 1:
                    header = parts[0]
                    enc_msg = parts[1].strip()
                    decrypted = decrypt_data(chat_key, enc_msg)
                    print(f"{header}\nDecrypted message: {decrypted}")
                else:
                    print(message)
            else:
                print(message)
        except Exception as e:
            print("Connection lost.")
            break

def main():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("127.0.0.1", 15000))
    
    # دریافت پیام خوشامدگویی از سرور
    print(client.recv(1024).decode())
    
    # حلقه ورود/ثبت‌نام تا زمانی که ورود موفق باشد
    login_success = False
    username = ""
    chat_key = None
    while not login_success:
        option = input("Do you want to (L)ogin or (R)egister? ").strip().lower()
        if option == 'l':
            username = input("Enter username: ")
            password = input("Enter password: ")
            client.send(f"Login {username} {password}\n".encode())
            response = client.recv(4096).decode().strip()
            print(response)
            if response.startswith("Key"):
                # دریافت کلید رمزنگاری از سرور
                encrypted_chat_key = response.split()[1]
                derived = derive_key(password)
                decrypted_key_str = decrypt_data(derived, encrypted_chat_key)
                try:
                    chat_key = base64.b64decode(decrypted_key_str)
                except Exception as e:
                    print(f"Error decoding chat key: {e}")
                    continue
                print(f"Chat key established for {username}.")
                login_success = True
            else:
                print("Login failed. Please try again or register.")
        elif option == 'r':
            username = input("Enter username for registration: ")
            password = input("Enter password for registration: ")
            client.send(f"Registration {username} {password}\n".encode())
            reg_response = client.recv(4096).decode().strip()
            print(reg_response)
            if reg_response.startswith("Registration successful"):
                print("You can now login.")
            else:
                print("Registration failed. Try a different username.")
        else:
            print("Invalid option. Please choose 'L' or 'R'.")
    
    # ارسال پیام Hello جهت اعلام ورود به تالار
    client.send(f"Hello {username}\n".encode())
    
    # شروع دریافت پیام‌ها
    thread = threading.Thread(target=receive_messages, args=(client, chat_key))
    thread.daemon = True
    thread.start()
    
    # حلقه اصلی ارسال پیام
    while True:
        command = input()
        if command.startswith("Private"):
            # دستور: Private <recipient> <message>
            parts = command.split(" ", 2)
            if len(parts) < 3:
                print("Invalid command. Use: Private <recipient> <message>")
                continue
            recipient, msg_body = parts[1], parts[2]
            encrypted_msg = encrypt_data(chat_key, msg_body)
            client.send(f"Private {username} {recipient} {encrypted_msg}\n".encode())
        else:
            client.send(f"{command}\n".encode())

if __name__ == "__main__":
    main()
