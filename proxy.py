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
from tkinter import ttk, font
from tkinter.scrolledtext import ScrolledText

# Configuration
HOST = '0.0.0.0'
PORT = 8888
BUFFER_SIZE = 4096
CACHE = {}
CACHE_EXPIRY = 60
MAX_WORKERS = 50

# Graceful shutdown support
is_running = True
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
            log_message("Malformed request received.", "lightpink")
            return

        if method == "CONNECT":
            handle_https_tunnel(client_socket, url)
        else:
            handle_http_request(client_socket, request, url)

    except Exception as e:
        log_message(f"\n\nError handling client: {e}", "lightpink")
    finally:
        client_socket.close()

def handle_http_request(client_socket, request, url):
    try:
        cache_key = get_cache_key(url)
        current_time = time.time()

        if cache_key in CACHE and (current_time - CACHE[cache_key]['timestamp'] < CACHE_EXPIRY):
            log_message(f"Cache hit for {url}", "lightgreen")
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
        log_message(f"\n\nHTTP Request Error: {e}", "lightpink")

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
        log_message(f"\n\nHTTPS Tunnel Error: {e}", "lightpink")

def start_proxy():
    proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    proxy_socket.bind((HOST, PORT))
    proxy_socket.listen(100)
    proxy_socket.settimeout(1.0)

    log_message(f"Proxy Server listening on {HOST}:{PORT}", "bold")

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        while is_running:
            try:
                client_socket, addr = proxy_socket.accept()
                log_message(f"\n\nAccepted connection from {addr}", "lightgreen")
                executor.submit(handle_client, client_socket)
            except socket.timeout:
                continue
            except Exception as e:
                log_message(f"Accept error: {e}", "lightpink")
                break

    proxy_socket.close()

def update_cache_listbox():
    if cache_listbox:
        cache_listbox.after(0, lambda: _update_cache_listbox())

def _update_cache_listbox():
    cache_listbox.delete(0, tk.END)
    for url in cached_urls:
        cache_listbox.insert(tk.END, url)

class GuiLogger:
    def __init__(self, text_widget):
        self.text_widget = text_widget

    def write(self, message):
        self.text_widget.after(0, lambda msg=message: self.insert_message(msg))

    def insert_message(self, message):
        self.text_widget.insert(tk.END, message)
        self.text_widget.see(tk.END)

    def flush(self):
        pass

def log_message(message, color=None):
    text_area.after(0, lambda: _log_message(message, color))

def _log_message(message, color=None):
    if color == "lightpink":
        text_area.tag_config('lightpink', foreground='lightpink')
        text_area.insert(tk.END, message + '\n', 'lightpink')
    elif color == "lightgreen":
        text_area.tag_config('lightgreen', foreground='lightgreen')
        text_area.insert(tk.END, message + '\n', 'lightgreen')
    elif color == "bold":
        text_area.tag_config('bold', font=('Arial', 10, 'bold'))
        text_area.insert(tk.END, message + '\n', 'bold')
    else:
        text_area.insert(tk.END, message + '\n')
    text_area.see(tk.END)

def launch_gui():
    def clear_log():
        text_area.delete('1.0', tk.END)

    def clear_cache():
        global cached_urls, CACHE
        cached_urls.clear()
        CACHE.clear()
        update_cache_listbox()

    def exit_gui():
        global is_running
        is_running = False
        root.destroy()

    global cache_listbox, text_area
    root = tk.Tk()
    root.title("Proxy Server")

    # Make the window full screen
    root.state('zoomed')  # For Windows
    root.attributes('-fullscreen', True)  # For Linux and macOS

    # Styling
    style = ttk.Style()
    style.configure('TButton', font=('Arial', 12, 'bold'), padding=10, background='white', foreground='black')

    # Control frame
    control_frame = ttk.Frame(root, padding=10)
    control_frame.pack(pady=5, anchor=tk.CENTER)

    # Create buttons
    clear_log_button = ttk.Button(control_frame, text="Clear Log", command=clear_log, style='TButton')
    exit_button = ttk.Button(control_frame, text="Exit", command=exit_gui, style='TButton')

    # Pack buttons to center them
    clear_log_button.pack(side=tk.LEFT, padx=5)
    exit_button.pack(side=tk.LEFT, padx=5)

    # Main frame
    main_frame = ttk.Frame(root, padding=10)
    main_frame.pack(fill=tk.BOTH, expand=True)

    # Text area
    text_area = ScrolledText(main_frame, wrap=tk.WORD, height=20, width=80, font=('Arial', 10))
    text_area.pack(side=tk.LEFT, padx=10, pady=5, fill=tk.BOTH, expand=True)

    # Right frame with label, button, and listbox
    right_frame = ttk.Frame(main_frame, padding=10)
    right_frame.pack(side=tk.RIGHT, padx=10, pady=5, fill=tk.BOTH, expand=True)

    ttk.Label(right_frame, text="Cached Websites", font=('Helvetica', 12, 'bold')).pack(anchor='n', pady=(0, 5))

    clear_cache_button = ttk.Button(right_frame, text="Clear Cache", command=clear_cache, style='TButton')
    clear_cache_button.pack(anchor='n', pady=(0, 10))

    cache_listbox = tk.Listbox(right_frame, height=20)
    cache_listbox.pack(fill=tk.BOTH, expand=True)

    # Redirect stdout and stderr to the GUI logger
    sys.stdout = GuiLogger(text_area)
    sys.stderr = GuiLogger(text_area)

    # Start proxy server in a separate thread
    threading.Thread(target=start_proxy, daemon=True).start()

    root.mainloop()

if __name__ == "__main__":
    # Set the signal handler
    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)
    launch_gui()
