import socket
import threading
import os
import time
import scapy.all as scapy
from cryptography.fernet import Fernet
from flask import Flask, render_template_string, request
from flask_socketio import SocketIO
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
socketio = SocketIO(app, async_mode='threading')

# Encryption setup
KEY_FILE = "key.key"

def load_key():
    """Load or generate encryption key"""
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as key_file:
            return key_file.read()
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as key_file:
        key_file.write(key)
    return key

encryption_key = load_key()
cipher = Fernet(encryption_key)

def encrypt_message(message):
    """Encrypt message using Fernet"""
    return cipher.encrypt(message.encode()).decode()

def decrypt_message(encrypted_message):
    """Decrypt message using Fernet"""
    try:
        return cipher.decrypt(encrypted_message.encode()).decode()
    except Exception as e:
        logger.error(f"Decryption failed: {e}")
        return f"[ERROR] Decryption failed: {e}"

# Network Server Implementation
class SecureServer:
    def __init__(self):
        self.running = False
        self.server_socket = None
        self.clients = []

    def start(self):
        """Start the secure server"""
        if self.running:
            socketio.emit('log', {'msg': '[WARNING] Server already running', 'type': 'warning'})
            return

        self.running = True
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.bind(("0.0.0.0", 9999))
            self.server_socket.listen(5)
            socketio.emit('log', {'msg': '[SERVER] Listening on 0.0.0.0:9999...', 'type': 'info'})
            
            while self.running:
                client_socket, addr = self.server_socket.accept()
                socketio.emit('log', {'msg': f'[SERVER] Connection from {addr}', 'type': 'success'})
                self.clients.append(client_socket)
                
                # Handle client in a new thread
                client_thread = threading.Thread(
                    target=self.handle_client, 
                    args=(client_socket,),
                    daemon=True
                )
                client_thread.start()
                
        except Exception as e:
            socketio.emit('log', {'msg': f'[SERVER ERROR] {e}', 'type': 'error'})
        finally:
            self.stop()

    def handle_client(self, client_socket):
        """Handle client connection"""
        try:
            while self.running:
                encrypted_data = client_socket.recv(1024).decode()
                if not encrypted_data:
                    break
                
                socketio.emit('log', {'msg': f'[ENCRYPTED] {encrypted_data}', 'type': 'encrypted'})
                decrypted_msg = decrypt_message(encrypted_data)
                socketio.emit('log', {'msg': f'[DECRYPTED] {decrypted_msg}', 'type': 'decrypted'})
                
                response = f"Server received: {decrypted_msg}"
                client_socket.send(encrypt_message(response).encode())
                
        except Exception as e:
            socketio.emit('log', {'msg': f'[CLIENT ERROR] {e}', 'type': 'error'})
        finally:
            client_socket.close()
            if client_socket in self.clients:
                self.clients.remove(client_socket)

    def stop(self):
        """Stop the server"""
        self.running = False
        for client in self.clients:
            client.close()
        if self.server_socket:
            self.server_socket.close()
        socketio.emit('log', {'msg': '[SERVER] Stopped', 'type': 'info'})

# Network Client Implementation
class SecureClient:
    def __init__(self, server_ip='127.0.0.1'):
        self.server_ip = server_ip
        self.client_socket = None
        self.connected = False

    def connect(self):
        """Connect to the server"""
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((self.server_ip, 9999))
            self.connected = True
            socketio.emit('log', {'msg': f'[CLIENT] Connected to {self.server_ip}:9999', 'type': 'success'})
            return True
        except Exception as e:
            socketio.emit('log', {'msg': f'[CLIENT ERROR] {e}', 'type': 'error'})
            return False

    def send_message(self, message):
        """Send a message to the server"""
        if not self.connected and not self.connect():
            return False

        try:
            encrypted_message = encrypt_message(message)
            self.client_socket.send(encrypted_message.encode())
            socketio.emit('log', {'msg': f'[SENT] {encrypted_message}', 'type': 'encrypted'})
            
            response = self.client_socket.recv(1024).decode()
            socketio.emit('log', {'msg': f'[RESPONSE] {decrypt_message(response)}', 'type': 'decrypted'})
            return True
        except Exception as e:
            socketio.emit('log', {'msg': f'[CLIENT ERROR] {e}', 'type': 'error'})
            self.connected = False
            return False

    def disconnect(self):
        """Disconnect from server"""
        if self.client_socket:
            self.client_socket.close()
        self.connected = False
        socketio.emit('log', {'msg': '[CLIENT] Disconnected', 'type': 'info'})

# Network Monitoring Implementation
class NetworkMonitor:
    def __init__(self):
        self.sniffer_running = False
        self.arp_detector_running = False

    def packet_sniffer(self, count=50):
        """Monitor network traffic for suspicious packets"""
        fake_mac_addresses = ["00:11:22:33:44:55", "66:77:88:99:AA:BB"]
        self.sniffer_running = True

        def process_packet(packet):
            if not self.sniffer_running:
                return
            if packet.haslayer(scapy.Ether):
                mac_src = packet[scapy.Ether].src
                if mac_src in fake_mac_addresses:
                    socketio.emit('log', {
                        'msg': f'[ALERT] Suspicious packet from fake MAC {mac_src}', 
                        'type': 'alert'
                    })
                else:
                    socketio.emit('log', {
                        'msg': f'[PACKET] {packet.summary()}', 
                        'type': 'info'
                    })

        try:
            socketio.emit('log', {
                'msg': '[SNIFFER] Starting packet monitoring...', 
                'type': 'info'
            })
            scapy.sniff(prn=process_packet, store=False, count=count)
        except Exception as e:
            socketio.emit('log', {
                'msg': f'[SNIFFER ERROR] {e}', 
                'type': 'error'
            })
        finally:
            self.sniffer_running = False
            socketio.emit('log', {
                'msg': '[SNIFFER] Stopped', 
                'type': 'info'
            })

    def stop_sniffer(self):
        """Stop the packet sniffer"""
        self.sniffer_running = False
        socketio.emit('log', {
            'msg': '[SNIFFER] Stopping...', 
            'type': 'info'
        })

    def arp_spoof_detector(self, count=50):
        """Detect ARP spoofing attempts"""
        fake_ip_list = ["192.168.1.100", "10.0.0.50","192.168.43.1"]
        ip_table = {}
        self.arp_detector_running = True

        def detect_arp_spoof(packet):
            if not self.arp_detector_running:
                return
            if packet.haslayer(scapy.ARP) and packet.op == 2:
                ip = packet.psrc
                if ip in fake_ip_list:
                    socketio.emit('log', {
                        'msg': f'[ALERT] ARP Spoofing! Fake IP: {ip}', 
                        'type': 'alert'
                    })
                elif ip in ip_table:
                    socketio.emit('log', {
                        'msg': f'[ALERT] ARP Spoofing! Duplicate IP: {ip}', 
                        'type': 'alert'
                    })
                else:
                    ip_table[ip] = True

        try:
            socketio.emit('log', {
                'msg': '[ARP] Monitoring ARP traffic...', 
                'type': 'info'
            })
            scapy.sniff(filter="arp", prn=detect_arp_spoof, store=False, count=count)
        except Exception as e:
            socketio.emit('log', {
                'msg': f'[ARP ERROR] {e}', 
                'type': 'error'
            })
        finally:
            self.arp_detector_running = False
            socketio.emit('log', {
                'msg': '[ARP] Stopped', 
                'type': 'info'
            })

    def stop_arp_detector(self):
        """Stop the ARP detector"""
        self.arp_detector_running = False
        socketio.emit('log', {
            'msg': '[ARP] Stopping...', 
            'type': 'info'
        })

# Initialize components
server = SecureServer()
client = SecureClient()
monitor = NetworkMonitor()

# Web Interface
html_template = """
<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='UTF-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
    <title>Secure Communication</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
    <style>
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            text-align: center;
            background-image: url('https://thumbs.dreamstime.com/b/multi-screen-representation-intrusion-detection-system-abstract-data-dashboards-graphs-live-network-traffic-344507977.jpg');
            background-size: cover;
            background-position: center;
            background-attachment: fixed;
            margin: 0;
            padding: 0;
            height: 100vh;
            color: #333;
        }
        .container { 
            width: 70%;
            max-width: 900px;
            margin: 30px auto;
            background: rgba(25, 28, 36, 0.85);
            padding: 25px;
            border-radius: 8px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
            backdrop-filter: blur(4px);
            border: 1px solid rgba(255, 255, 255, 0.1);
        }
        h1 {
            color: #4CAF50;
            margin-bottom: 25px;
            font-weight: 600;
            text-shadow: 0 2px 4px rgba(0,0,0,0.3);
        }
        .panel {
            margin-bottom: 20px;
            padding: 15px;
            background: rgba(10, 12, 16, 0.5);
            border-radius: 6px;
        }
        .btn-group {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin-bottom: 15px;
            justify-content: center;
        }
        button {
            padding: 12px 24px;
            font-size: 16px;
            cursor: pointer;
            background: linear-gradient(135deg, #4CAF50 0%, #2E7D32 100%);
            color: white;
            border: none;
            border-radius: 6px;
            transition: all 0.3s ease;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            font-weight: 500;
            min-width: 180px;
        }
        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 8px rgba(0,0,0,0.15);
            background: linear-gradient(135deg, #43A047 0%, #1B5E20 100%);
        }
        button:active {
            transform: translateY(0);
        }
        button.stop {
            background: linear-gradient(135deg, #f44336 0%, #c62828 100%);
        }
        button.stop:hover {
            background: linear-gradient(135deg, #e53935 0%, #b71c1c 100%);
        }
        #log {
            text-align: left;
            height: 300px;
            overflow-y: auto;
            background: rgba(10, 12, 16, 0.7);
            color: #f0f0f0;
            padding: 15px;
            border-radius: 6px;
            font-family: 'Consolas', 'Monaco', monospace;
            border: 1px solid rgba(255, 255, 255, 0.1);
            box-shadow: inset 0 1px 3px rgba(0,0,0,0.5);
        }
        .log-info {
            color: #64B5F6;
        }
        .log-success {
            color: #81C784;
        }
        .log-error {
            color: #FF5252;
            font-weight: bold;
        }
        .log-alert {
            color: #FF8A65;
            font-weight: bold;
        }
        .log-encrypted {
            color: #BA68C8;
        }
        .log-decrypted {
            color: #4DB6AC;
        }
        .log-warning {
            color: #FFD54F;
        }
        .input-group {
            display: flex;
            gap: 10px;
            margin-bottom: 15px;
        }
        input {
            flex-grow: 1;
            padding: 12px;
            background: rgba(255,255,255,0.1);
            border: 1px solid rgba(255,255,255,0.2);
            border-radius: 6px;
            color: white;
            font-size: 16px;
        }
        input::placeholder {
            color: rgba(255,255,255,0.5);
        }
        .status {
            margin-top: 10px;
            font-weight: bold;
            color: #4CAF50;
        }
        ::-webkit-scrollbar {
            width: 8px;
        }
        ::-webkit-scrollbar-track {
            background: rgba(255,255,255,0.05);
        }
        ::-webkit-scrollbar-thumb {
            background: rgba(255,255,255,0.2);
            border-radius: 4px;
        }
        ::-webkit-scrollbar-thumb:hover {
            background: rgba(255,255,255,0.3);
        }
    </style>
</head>
<body>
    <div class='container'>
        <h1>Secure Communication & Intrusion Detection System</h1>
        
        <div class="panel">
            <h2>Secure Server</h2>
            <div class="btn-group">
                <button onclick="startServer()">Start Server</button>
                <button onclick="stopServer()" class="stop">Stop Server</button>
            </div>
            <div id="server-status" class="status">Status: Not running</div>
        </div>
        
        <div class="panel">
            <h2>Secure Client</h2>
            <div class="input-group">
                <input type="text" id="server-ip" placeholder="Server IP" value="127.0.0.1">
                <button onclick="updateServerIp()">Update IP</button>
            </div>
            <div class="input-group">
                <input type="text" id="message-input" placeholder="Enter message to send">
                <button onclick="sendMessage()">Send Message</button>
            </div>
            <div id="client-status" class="status">Status: Disconnected</div>
        </div>
        
        <div class="panel">
            <h2>Network Monitoring</h2>
            <div class="btn-group">
                <button onclick="startSniffer()">Start Packet Sniffer</button>
                <button onclick="stopSniffer()" class="stop">Stop Sniffer</button>
                <button onclick="startARP()">Start ARP Detector</button>
                <button onclick="stopARP()" class="stop">Stop ARP Detector</button>
            </div>
        </div>
        
        <div class="panel">
            <h2>Activity Log</h2>
            <div id='log'></div>
        </div>
    </div>
    
    <script>
        const socket = io();
        let serverRunning = false;
        let clientConnected = false;
        
        // Display logs with appropriate styling
        socket.on('log', function(data) {
            const logDiv = document.getElementById('log');
            const logEntry = document.createElement('div');
            logEntry.className = `log-${data.type}`;
            logEntry.textContent = data.msg;
            logDiv.appendChild(logEntry);
            logDiv.scrollTop = logDiv.scrollHeight;
            
            // Update status indicators
            updateStatusIndicators(data);
        });
        
        function updateStatusIndicators(data) {
            // Server status updates
            if (data.msg.includes('[SERVER] Listening')) {
                serverRunning = true;
                document.getElementById('server-status').textContent = 'Status: Running';
                document.getElementById('server-status').style.color = '#81C784';
            }
            if (data.msg.includes('[SERVER] Stopped')) {
                serverRunning = false;
                document.getElementById('server-status').textContent = 'Status: Not running';
                document.getElementById('server-status').style.color = '#FF5252';
            }
            
            // Client status updates
            if (data.msg.includes('[CLIENT] Connected')) {
                clientConnected = true;
                document.getElementById('client-status').textContent = 'Status: Connected';
                document.getElementById('client-status').style.color = '#81C784';
            }
            if (data.msg.includes('[CLIENT] Disconnected')) {
                clientConnected = false;
                document.getElementById('client-status').textContent = 'Status: Disconnected';
                document.getElementById('client-status').style.color = '#FF5252';
            }
        }
        
        // Server controls
        function startServer() { 
            fetch('/start_server')
                .then(res => res.text())
                .then(text => console.log(text))
                .catch(err => console.error('Error:', err));
        }
        
        function stopServer() {
            fetch('/stop_server')
                .then(res => res.text())
                .then(text => console.log(text))
                .catch(err => console.error('Error:', err));
        }
        
        // Client controls
        function updateServerIp() {
            const ip = document.getElementById('server-ip').value.trim();
            fetch('/update_ip', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip: ip })
            })
            .then(res => res.text())
            .then(text => console.log(text))
            .catch(err => console.error('Error:', err));
        }
        
        function sendMessage() {
            const input = document.getElementById('message-input');
            const message = input.value.trim();
            if (message) {
                fetch('/send_message', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ message: message })
                })
                .then(res => res.text())
                .then(text => console.log(text))
                .catch(err => console.error('Error:', err));
                input.value = '';
            }
        }
        
        // Network monitoring controls
        function startSniffer() {
            fetch('/start_sniffer')
                .then(res => res.text())
                .then(text => console.log(text))
                .catch(err => console.error('Error:', err));
        }
        
        function stopSniffer() {
            fetch('/stop_sniffer')
                .then(res => res.text())
                .then(text => console.log(text))
                .catch(err => console.error('Error:', err));
        }
        
        function startARP() {
            fetch('/start_arp')
                .then(res => res.text())
                .then(text => console.log(text))
                .catch(err => console.error('Error:', err));
        }
        
        function stopARP() {
            fetch('/stop_arp')
                .then(res => res.text())
                .then(text => console.log(text))
                .catch(err => console.error('Error:', err));
        }
        
        // Allow sending with Enter key
        document.getElementById('message-input').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') sendMessage();
        });
    </script>
</body>
</html>
"""

# Flask routes
@app.route('/')
def home():
    return render_template_string(html_template)

@app.route('/start_server')
def start_server():
    threading.Thread(target=server.start, daemon=True).start()
    return "Server starting in background..."

@app.route('/stop_server')
def stop_server():
    server.stop()
    return "Server stop requested"

@app.route('/update_ip', methods=['POST'])
def update_ip():
    data = request.get_json()
    if not data or 'ip' not in data:
        return "No IP provided", 400
    client.server_ip = data['ip']
    return f"Client server IP updated to {data['ip']}"

@app.route('/send_message', methods=['POST'])
def send_message():
    data = request.get_json()
    if not data or 'message' not in data:
        return "No message provided", 400
    
    if client.send_message(data['message']):
        return f"Message sent: {data['message']}"
    return "Failed to send message", 500

@app.route('/start_sniffer')
def start_sniffer():
    threading.Thread(target=monitor.packet_sniffer, daemon=True).start()
    return "Packet sniffer started in background..."

@app.route('/stop_sniffer')
def stop_sniffer():
    monitor.stop_sniffer()
    return "Packet sniffer stop requested"

@app.route('/start_arp')
def start_arp():
    threading.Thread(target=monitor.arp_spoof_detector, daemon=True).start()
    return "ARP spoof detector started in background..."

@app.route('/stop_arp')
def stop_arp():
    monitor.stop_arp_detector()
    return "ARP spoof detector stop requested"

# SocketIO events
@socketio.on('connect')
def handle_connect():
    socketio.emit('log', {'msg': '[SYSTEM] Web client connected', 'type': 'info'})

@socketio.on('disconnect')
def handle_disconnect():
    socketio.emit('log', {'msg': '[SYSTEM] Web client disconnected', 'type': 'info'})

if __name__ == '__main__':
    logger.info("Starting application...")
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)