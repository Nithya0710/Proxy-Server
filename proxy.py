# proxy_server_gui.py

import socket
import threading
import select
import hashlib
import time
import signal
import sys
import logging
from concurrent.futures import ThreadPoolExecutor
import tkinter as tk
from tkinter.scrolledtext import ScrolledText

# Configuration
HOST = '0.0.0.0'
PORT = 8888
BUFFER_SIZE = 4096
CACHE = {}
CACHE_EXPIRY = 60
MAX_WORKERS = 50

# Logging to GUI
class GuiLogger:
    def __init__(self, text_widget):
        self.text_widget = text_widget

    def write(self, message):
        self.text_widget.after(0, self.text_widget.insert, tk.END, message)
        self.text_widget.after(0, self.text_widget.see, tk.END)

    def flush(self):
        pass

# Graceful shutdown support
is_running = True

# Track cached URLs
cached_urls = []

cache_listbox = None

def shutdown_handler(signum, frame):
    global is_running
    print("Shutting down proxy server...")
    is_running = False

signal.signal(signal.SIGINT, shutdown_handler)
signal.signal(signal.SIGTERM, shutdown_handler)

def get_cache_key(url):
    return hashlib.md5(url.encode()).hexdigest()

def parse_request(request):
    try:
        lines = request.split('\r\n')
        method, url, version = lines[0].split(' ')
        return method, url, version
    except ValueError:
        return None, None, None

def record_url(url):
    if url.startswith("www.") and url not in cached_urls:
        cached_urls.append(url)
        update_cache_listbox()

def handle_client(client_socket):
    try:
        request = b''
        while True:
            chunk = client_socket.recv(BUFFER_SIZE)
            request += chunk
            if b'\r\n\r\n' in request or not chunk:
                break

        if not request:
            return

        request_str = request.decode('utf-8', errors='ignore')
        method, url, version = parse_request(request_str)

        if method is None:
            print("Malformed request received.")
            return

        if method == "CONNECT":
            handle_https_tunnel(client_socket, url)
        else:
            handle_http_request(client_socket, request, url)

    except Exception as e:
        print(f"Error handling client: {e}")
    finally:
        client_socket.close()

def handle_http_request(client_socket, request, url):
    try:
        cache_key = get_cache_key(url)
        current_time = time.time()

        if cache_key in CACHE and (current_time - CACHE[cache_key]['timestamp'] < CACHE_EXPIRY):
            print(f"Cache hit for {url}")
            client_socket.sendall(CACHE[cache_key]['response'])
            return

        http_pos = url.find('://')
        if http_pos != -1:
            url = url[(http_pos+3):]

        port_pos = url.find(':')
        path_pos = url.find('/')
        if path_pos == -1:
            path_pos = len(url)

        port = 80 if port_pos == -1 or port_pos > path_pos else int(url[(port_pos+1):path_pos])
        host = url[:port_pos] if port_pos != -1 and port_pos < path_pos else url[:path_pos]

        server_socket = socket.create_connection((host, port))
        server_socket.sendall(request)

        response_data = b""
        while True:
            response = server_socket.recv(BUFFER_SIZE)
            if not response:
                break
            response_data += response
            client_socket.sendall(response)

        CACHE[cache_key] = {'response': response_data, 'timestamp': time.time()}

        record_url(url)

        server_socket.close()
    except Exception as e:
        print(f"HTTP Request Error: {e}")

def handle_https_tunnel(client_socket, url):
    try:
        host, port = url.split(':')
        port = int(port)

        server_socket = socket.create_connection((host, port))
        client_socket.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

        record_url(host)

        sockets = [client_socket, server_socket]
        while True:
            r, _, _ = select.select(sockets, [], [], 10)
            if not r:
                break
            for sock in r:
                data = sock.recv(BUFFER_SIZE)
                if not data:
                    return
                if sock is client_socket:
                    server_socket.sendall(data)
                else:
                    client_socket.sendall(data)
    except Exception as e:
        print(f"HTTPS Tunnel Error: {e}")

def start_proxy():
    proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    proxy_socket.bind((HOST, PORT))
    proxy_socket.listen(100)
    proxy_socket.settimeout(1.0)

    print(f"Proxy Server listening on {HOST}:{PORT}")

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        while is_running:
            try:
                client_socket, addr = proxy_socket.accept()
                print(f"Accepted connection from {addr}")
                executor.submit(handle_client, client_socket)
            except socket.timeout:
                continue
            except Exception as e:
                print(f"Accept error: {e}")
                break

    proxy_socket.close()

def update_cache_listbox():
    if cache_listbox:
        cache_listbox.after(0, lambda: _update_cache_listbox())

def _update_cache_listbox():
    cache_listbox.delete(0, tk.END)
    for url in cached_urls:
        cache_listbox.insert(tk.END, url)

def launch_gui():
    def clear_log():
        text_area.delete('1.0', tk.END)

    def exit_gui():
        global is_running
        is_running = False
        root.destroy()

    global cache_listbox

    root = tk.Tk()
    root.title("Proxy Server Control Panel")

    control_frame = tk.Frame(root)
    tk.Button(control_frame, text="Clear Log", command=clear_log).pack(side=tk.LEFT, padx=5)
    tk.Button(control_frame, text="Exit", command=exit_gui).pack(side=tk.LEFT, padx=5)
    control_frame.pack(pady=5, anchor=tk.W)

    main_frame = tk.Frame(root)
    main_frame.pack(fill=tk.BOTH, expand=True)

    text_area = ScrolledText(main_frame, wrap=tk.WORD, height=20, width=80)
    text_area.pack(side=tk.LEFT, padx=10, pady=5, fill=tk.BOTH, expand=True)

    cache_listbox = tk.Listbox(main_frame, height=20, width=40)
    cache_listbox.pack(side=tk.RIGHT, padx=10, pady=5, fill=tk.Y)

    sys.stdout = GuiLogger(text_area)
    sys.stderr = GuiLogger(text_area)

    threading.Thread(target=start_proxy, daemon=True).start()
    root.mainloop()

if __name__ == "__main__":
    launch_gui()
