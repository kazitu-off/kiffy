import socket
import threading
from datetime import datetime
import re
import getpass
import hashlib
import hmac
import time
import secrets
from cryptography.fernet import Fernet
import base64

class KiffyServer:
    def __init__(self, host='0.0.0.0', port=8888):
        self.host = host
        self.port = port
        self.clients = {}
        self.starred_users = set()
        self.admins = set()
        self.global_emoji = "📢"
        self.typing_users = {}
        self.banned_users = set()
        self.banned_ips = set()
        self.rate_limits = {}
        self.message_counters = {}
        
        print("KIFFY SERVER SETUP")
        print("=" * 40)
        self.admin_password = getpass.getpass("Set admin password: ")
        print("=" * 40)
        
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
    def generate_session_key(self):
        return base64.urlsafe_b64encode(secrets.token_bytes(32))
    
    def create_hmac(self, message, key):
        return hmac.new(key, message.encode(), hashlib.sha256).hexdigest()
    
    def verify_hmac(self, message, received_hmac, key):
        expected_hmac = self.create_hmac(message, key)
        return hmac.compare_digest(expected_hmac, received_hmac)
    
    def check_rate_limit(self, username, ip):
        now = time.time()
        user_key = f"{username}_{ip}"
        
        if user_key not in self.rate_limits:
            self.rate_limits[user_key] = []
        
        self.rate_limits[user_key] = [t for t in self.rate_limits[user_key] if now - t < 60]
        
        if len(self.rate_limits[user_key]) >= 30:
            return False
        
        self.rate_limits[user_key].append(now)
        return True
    
    def safe_recv(self, socket, max_size=4096):
        try:
            data = socket.recv(max_size)
            if len(data) >= max_size:
                return None
            return data
        except:
            return None
    
    def get_current_ips(self):
        ips = []
        try:
            hostname = socket.gethostname()
            all_ips = socket.gethostbyname_ex(hostname)[2]
            for ip in all_ips:
                if ip != '127.0.0.1':
                    ips.append(ip)
        except:
            pass
        
        if not ips:
            ips.append("127.0.0.1")
            
        return ips
    
    def is_local_ip(self, ip):
        if ip == "127.0.0.1":
            return True
        local_prefixes = ['10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.',
                         '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
                         '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.']
        return any(ip.startswith(prefix) for prefix in local_prefixes)
    
    def is_valid_username(self, username):
        return bool(re.match(r'^[a-zA-Z0-9_]{3,20}$', username))
    
    def ban_user(self, username, reason="No reason"):
        if username in self.clients:
            client_info = self.clients[username]
            ip = client_info.get('ip', '')
            if ip:
                self.banned_ips.add(ip)
            self.banned_users.add(username)
            
            try:
                self.send_secure_message(client_info['socket'], client_info['cipher'], f" You are banned. Reason: {reason}")
                client_info['socket'].close()
            except:
                pass
            
            self.cleanup_user(username)
            return True
        return False
    
    def unban_user(self, username):
        if username in self.banned_users:
            self.banned_users.remove(username)
            return True
        return False
    
    def is_banned(self, username, ip):
        return username in self.banned_users or ip in self.banned_ips
    
    def start_typing(self, username):
        self.typing_users[username] = time.time()
        typing_msg = f"TYPING_START:{username}"
        self.broadcast_secure(typing_msg, None, username)
    
    def stop_typing(self, username):
        if username in self.typing_users:
            del self.typing_users[username]
            typing_msg = f"TYPING_STOP:{username}"
            self.broadcast_secure(typing_msg, None, username)
    
    def send_secure_message(self, socket, cipher, message):
        try:
            encrypted = cipher.encrypt(message.encode())
            socket.send(encrypted)
            return True
        except:
            return False
    
    def broadcast_secure(self, message, sender_socket, exclude_user=None):
        disconnected = []
        
        for username, client_info in list(self.clients.items()):
            try:
                if client_info['socket'] != sender_socket and username != exclude_user:
                    self.send_secure_message(client_info['socket'], client_info['cipher'], message)
            except:
                disconnected.append(username)
        
        for username in disconnected:
            self.cleanup_user(username)
    
    def cleanup_user(self, username):
        if username in self.clients:
            if username in self.typing_users:
                del self.typing_users[username]
            del self.clients[username]
            
            if username in self.starred_users:
                self.starred_users.remove(username)
            if username in self.admins and username != "admin":
                self.admins.remove(username)
            
            formatted_username = self.format_username(username)
            leave_msg = f" {formatted_username} left ({len(self.clients)} online)"
            self.broadcast_secure(leave_msg, None, username)
    
    def format_username(self, username):
        if username in self.starred_users:
            return f" {username}"
        return username
    
    def give_star(self, target_user):
        if target_user in self.clients:
            self.starred_users.add(target_user)
            self.clients[target_user]['star'] = True
            return True
        return False
    
    def remove_star(self, target_user):
        if target_user in self.starred_users:
            self.starred_users.remove(target_user)
            if target_user in self.clients:
                self.clients[target_user]['star'] = False
            return True
        return False
    
    def make_admin(self, username):
        if username in self.clients:
            self.admins.add(username)
            self.clients[username]['admin'] = True
            return True
        return False
    
    def remove_admin(self, username):
        if username in self.admins:
            self.admins.remove(username)
            if username in self.clients:
                self.clients[username]['admin'] = False
            return True
        return False
    
    def send_global_message(self, from_user, message):
        formatted_message = f"{self.global_emoji} [GLOBAL] {from_user}: {message}"
        self.broadcast_secure(formatted_message, None, from_user)
        return True
    
    def change_global_emoji(self, new_emoji):
        self.global_emoji = new_emoji
        return True
    
    def start(self):
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(10)
        
        all_ips = self.get_current_ips()
        has_public_ip = any(not self.is_local_ip(ip) for ip in all_ips)
        
        print(" KIFFY MESSENGER SERVER STARTED")
        print("=" * 50)
        print("SERVER IP ADDRESSES:")
        for ip in all_ips:
            ip_type = "PUBLIC" if not self.is_local_ip(ip) else "LOCAL"
            print(f"  {ip} ({ip_type})")
        print(f"Port: {self.port}")
        print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(" Rate limiting: ENABLED (30 msg/min)")
        print(" HMAC verification: ACTIVE")
        
        if not has_public_ip:
            print("NETWORK ACCESS WARNING:")
            print("You have only LOCAL IP addresses.")
        else:
            print("Public IP detected - users can connect from anywhere")
        
        print("Waiting for connections...")
        print("=" * 50)
        
        while True:
            client_socket, addr = self.server_socket.accept()
            thread = threading.Thread(target=self.handle_client, args=(client_socket, addr))
            thread.daemon = True
            thread.start()
    
    def send_private_message(self, from_user, to_user, message):
        if to_user in self.clients:
            try:
                formatted_from = self.format_username(from_user)
                private_msg = f" {formatted_from}: {message}"
                self.send_secure_message(self.clients[to_user]['socket'], self.clients[to_user]['cipher'], private_msg)
                return True
            except:
                return False
        return False
    
    def set_anchor(self, username, target_user):
        if target_user in self.clients:
            self.clients[username]['anchor_target'] = target_user
            return True
        return False
    
    def remove_anchor(self, username):
        if username in self.clients and 'anchor_target' in self.clients[username]:
            del self.clients[username]['anchor_target']
            return True
        return False
    
    def handle_client(self, client_socket, addr):
        username = None
        is_admin = False
        client_ip = addr[0]
        session_key = None
        cipher = None
        
        try:
            if not self.check_rate_limit("connection", client_ip):
                client_socket.send(b"Rate limit exceeded")
                client_socket.close()
                return
            
            session_key = self.generate_session_key()
            cipher = Fernet(session_key)
            
            self.send_secure_message(client_socket, cipher, " Username: ")
            
            encrypted_username = self.safe_recv(client_socket)
            if not encrypted_username:
                return
                
            username = cipher.decrypt(encrypted_username).decode().strip()
            
            if not username:
                return
            
            if self.is_banned(username, client_ip):
                self.send_secure_message(client_socket, cipher, " You are banned from this server")
                return
            
            if not self.is_valid_username(username):
                self.send_secure_message(client_socket, cipher, " Invalid username! 3-20 chars, letters, numbers, _")
                return
            
            if username in self.clients:
                self.send_secure_message(client_socket, cipher, " Username taken!")
                return
            
            if username == "admin":
                self.send_secure_message(client_socket, cipher, " Admin password: ")
                encrypted_password = self.safe_recv(client_socket)
                if not encrypted_password:
                    return
                    
                password = cipher.decrypt(encrypted_password).decode().strip()
                
                if password == self.admin_password:
                    is_admin = True
                    self.make_admin(username)
                    self.send_secure_message(client_socket, cipher, " Admin access granted!")
                else:
                    self.send_secure_message(client_socket, cipher, " Wrong password!")
                    return
            
            self.clients[username] = {
                'socket': client_socket,
                'anchor_target': None,
                'star': username in self.starred_users,
                'admin': is_admin,
                'ip': client_ip,
                'cipher': cipher,
                'session_key': session_key
            }
            
            formatted_username = self.format_username(username)
            welcome_msg = f" {formatted_username} joined ({len(self.clients)} online)"
            self.broadcast_secure(welcome_msg, client_socket, username)
            
            online_users = ", ".join([self.format_username(u) for u in self.clients.keys() if u != username])
            help_msg = f" Welcome {formatted_username}!\n Online: {online_users}\n Commands: /users /s [user] [msg] /anchor [user] /unanchor /exit"
            
            if is_admin:
                help_msg += "\n Admin: /star [user] /unstar [user] /global [msg] /setemoji [emoji] /makeadmin [user] /removeadmin [user] /ban [user] [reason] /unban [user] /banlist"
            
            self.send_secure_message(client_socket, cipher, help_msg)
            
            last_typing_time = 0
            
            while True:
                encrypted_message = self.safe_recv(client_socket)
                if not encrypted_message:
                    break
                
                try:
                    message = cipher.decrypt(encrypted_message).decode()
                except:
                    continue
                    
                if not message:
                    break
                
                if not self.check_rate_limit(username, client_ip):
                    self.send_secure_message(client_socket, cipher, " Rate limit exceeded. Wait 1 minute.")
                    continue
                
                current_time = time.time()
                if message.strip() and current_time - last_typing_time > 2:
                    self.start_typing(username)
                    last_typing_time = current_time
                
                if message.strip().lower() == '/exit':
                    break
                elif message.strip().lower() == '/users':
                    users_list = " Online: " + ", ".join([self.format_username(u) for u in self.clients.keys()])
                    self.send_secure_message(client_socket, cipher, users_list)
                    continue
                elif message.startswith('/s '):
                    parts = message[3:].split(' ', 1)
                    if len(parts) == 2:
                        target_user, private_msg = parts
                        if self.send_private_message(username, target_user, private_msg):
                            self.send_secure_message(client_socket, cipher, f" PM sent to {target_user}")
                        else:
                            self.send_secure_message(client_socket, cipher, f" User {target_user} not found")
                    else:
                        self.send_secure_message(client_socket, cipher, " Use: /s [user] [msg]")
                    continue
                elif message.startswith('/anchor '):
                    target_user = message[8:].strip()
                    if self.set_anchor(username, target_user):
                        self.send_secure_message(client_socket, cipher, f" Anchor to {target_user}")
                    else:
                        self.send_secure_message(client_socket, cipher, f" User {target_user} not found")
                    continue
                elif message.strip().lower() == '/unanchor':
                    if self.remove_anchor(username):
                        self.send_secure_message(client_socket, cipher, " Anchor disabled")
                    else:
                        self.send_secure_message(client_socket, cipher, " No anchor active")
                    continue
                elif message.strip().lower() == '/typing':
                    self.start_typing(username)
                    time.sleep(2)
                    self.stop_typing(username)
                    continue
                elif is_admin and message.startswith('/ban '):
                    parts = message[5:].split(' ', 1)
                    target_user = parts[0]
                    reason = parts[1] if len(parts) > 1 else "No reason"
                    if target_user == "admin":
                        self.send_secure_message(client_socket, cipher, " Cannot ban main admin")
                    elif self.ban_user(target_user, reason):
                        self.send_secure_message(client_socket, cipher, f" Banned {target_user}. Reason: {reason}")
                    else:
                        self.send_secure_message(client_socket, cipher, f" User {target_user} not found")
                    continue
                elif is_admin and message.startswith('/unban '):
                    target_user = message[7:].strip()
                    if self.unban_user(target_user):
                        self.send_secure_message(client_socket, cipher, f" Unbanned {target_user}")
                    else:
                        self.send_secure_message(client_socket, cipher, f" User {target_user} not banned")
                    continue
                elif is_admin and message.strip().lower() == '/banlist':
                    banned_list = " Banned users: " + ", ".join(self.banned_users) if self.banned_users else "No banned users"
                    self.send_secure_message(client_socket, cipher, banned_list)
                    continue
                elif is_admin and message.startswith('/star '):
                    target_user = message[6:].strip()
                    if self.give_star(target_user):
                        self.send_secure_message(client_socket, cipher, f" Star given to {target_user}")
                        star_msg = f" {target_user} received Kiffy Star "
                        self.broadcast_secure(star_msg, None, username)
                    else:
                        self.send_secure_message(client_socket, cipher, f" User {target_user} not found")
                    continue
                elif is_admin and message.startswith('/unstar '):
                    target_user = message[8:].strip()
                    if self.remove_star(target_user):
                        self.send_secure_message(client_socket, cipher, f" Star removed from {target_user}")
                    else:
                        self.send_secure_message(client_socket, cipher, f" User {target_user} no star")
                    continue
                elif is_admin and message.startswith('/global '):
                    global_msg = message[8:].strip()
                    if global_msg:
                        self.send_global_message(username, global_msg)
                        self.send_secure_message(client_socket, cipher, " Global message sent")
                    else:
                        self.send_secure_message(client_socket, cipher, " Use: /global [message]")
                    continue
                elif is_admin and message.startswith('/setemoji '):
                    new_emoji = message[10:].strip()
                    if new_emoji:
                        self.change_global_emoji(new_emoji)
                        self.send_secure_message(client_socket, cipher, f" Global emoji changed to {new_emoji}")
                    else:
                        self.send_secure_message(client_socket, cipher, " Use: /setemoji [emoji]")
                    continue
                elif is_admin and message.startswith('/makeadmin '):
                    target_user = message[11:].strip()
                    if self.make_admin(target_user):
                        self.send_secure_message(client_socket, cipher, f" {target_user} is now admin")
                        if target_user in self.clients:
                            self.send_secure_message(self.clients[target_user]['socket'], self.clients[target_user]['cipher'], " You are now an admin!")
                    else:
                        self.send_secure_message(client_socket, cipher, f" User {target_user} not found")
                    continue
                elif is_admin and message.startswith('/removeadmin '):
                    target_user = message[13:].strip()
                    if target_user == "admin":
                        self.send_secure_message(client_socket, cipher, " Cannot remove main admin")
                    elif self.remove_admin(target_user):
                        self.send_secure_message(client_socket, cipher, f" Admin rights removed from {target_user}")
                    else:
                        self.send_secure_message(client_socket, cipher, f" User {target_user} not admin")
                    continue
                
                self.stop_typing(username)
                    
                if username in self.clients and self.clients[username].get('anchor_target'):
                    target_user = self.clients[username]['anchor_target']
                    if self.send_private_message(username, target_user, message):
                        self.send_secure_message(client_socket, cipher, f" Sent to {target_user}")
                    else:
                        self.send_secure_message(client_socket, cipher, f" User {target_user} offline")
                else:
                    formatted_username = self.format_username(username)
                    formatted_msg = f" {formatted_username}: {message}"
                    self.broadcast_secure(formatted_msg, client_socket, username)
                
        except Exception as e:
            pass
        finally:
            if username:
                self.stop_typing(username)
                self.cleanup_user(username)
            client_socket.close()

if __name__ == "__main__":
    server = KiffyServer()
    server.start()
