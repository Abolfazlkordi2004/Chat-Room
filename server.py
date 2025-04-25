import socket
import threading
import base64
import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# دیکشنری‌های ذخیره اطلاعات
users = {}       # {username: password}
clients = {}     # {username: (conn, addr)}
chat_keys = {}   # {username: chat_key}

# تنظیمات سرور
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("0.0.0.0", 15000))
server.listen(5)

# تابع تولید کلید رمزنگاری از گذرواژه (SHA256)
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

# ارسال پیام به تمامی کاربران (broadcast) به جز فرستنده
def broadcast(message, sender):
    for user, (conn, _) in clients.items():
        if user != sender:
            try:
                conn.send(f"{message}\n".encode())
            except:
                pass

def handle_client(conn, addr):
    try:
        conn.send(b"Welcome to the Chat Server. Please register or login.\n")
        username = None
        while True:
            data = conn.recv(4096).decode().strip()
            if not data:
                break
            parts = data.split()
            command = parts[0]
            
            if command == "Registration":
                # Registration <user_name> <password>
                username, password = parts[1], parts[2]
                if username in users:
                    conn.send(b"Username already taken.\n")
                else:
                    users[username] = password
                    conn.send(b"Registration successful.\n")
            
            elif command == "Login":
                # Login <user_name> <password>
                username, password = parts[1], parts[2]
                if username not in users or users[username] != password:
                    conn.send(b"User not found or incorrect password.\n")
                else:
                    # ورود موفق؛ تولید یک chat key تصادفی
                    chat_key = os.urandom(32)
                    chat_keys[username] = chat_key
                    clients[username] = (conn, addr)
                    # رمزنگاری chat key با کلید مشتق‌شده از گذرواژه
                    derived = derive_key(password)
                    encrypted_chat_key = encrypt_data(derived, base64.b64encode(chat_key).decode())
                    # ارسال پیام به کاربر: Key <encrypted_chat_key>
                    conn.send(f"Key {encrypted_chat_key}\n".encode())
                    # ارسال پیام ورود به تمامی کاربران
                    broadcast(f"{username} join the chat room.", username)
            
            elif command == "Hello":
                # Hello <user_name>
                hello_user = parts[1]
                if hello_user in clients:
                    conn.send(f"Hi {hello_user}, welcome to the chat room.\n".encode())
            
            elif command == "List":
                # ارسال لیست حضار
                attendees = ", ".join(clients.keys())
                conn.send(f"Here is the list of attendees:\n{attendees}\n".encode())
            
            elif command == "Public":
                # Public <user_name> <message>
                sender = parts[1]
                message_body = " ".join(parts[2:])
                broadcast(f"Public message from {sender}, length={len(message_body)}:\n{message_body}", sender)
            
            elif command == "Private":
                # Private <sender> <recipient> <encrypted_message>
                sender = parts[1]
                recipient = parts[2]
                encrypted_msg = " ".join(parts[3:])
                if recipient not in clients:
                    conn.send(f"⚠️ User {recipient} is not online.\n".encode())
                    continue
                # سرور ابتدا پیام خصوصی را با chat key فرستنده رمزگشایی می‌کند
                decrypted_msg = decrypt_data(chat_keys[sender], encrypted_msg)
                # سپس پیام را با chat key گیرنده رمزنگاری می‌کند
                re_encrypted_msg = encrypt_data(chat_keys[recipient], decrypted_msg)
                # ارسال پیام به گیرنده
                clients[recipient][0].send(f"Private message, length={len(decrypted_msg)} from {sender} to {recipient}:\n{re_encrypted_msg}\n".encode())
                conn.send(f"✅ Private message sent to {recipient}.\n".encode())
            
            elif command == "Bye":
                # Bye <user_name>
                bye_user = parts[1]
                if bye_user in clients:
                    broadcast(f"{bye_user} left the chat room.", bye_user)
                    del clients[bye_user]
                    del chat_keys[bye_user]
                conn.send(b"Goodbye.\n")
                conn.close()
                break
            
            else:
                conn.send(b"Invalid command.\n")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()

print("Server is running on port 15000...")
while True:
    conn, addr = server.accept()
    threading.Thread(target=handle_client, args=(conn, addr)).start()
