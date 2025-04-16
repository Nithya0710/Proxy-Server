import socket
import threading
import select
import hashlib
import time

# Proxy Server Configuration
HOST = '0.0.0.0'  # Listen on all interfaces
PORT = 8888       # Port for the proxy server
BUFFER_SIZE = 4096
CACHE = {}  # Dictionary to store cached responses
CACHE_EXPIRY = 60  # Cache expiration time in seconds

def get_cache_key(url):
    """Generates a cache key using a hash of the URL."""
    return hashlib.md5(url.encode()).hexdigest()

def handle_client(client_socket):
    """Handles client request, forwards to target server, and relays the response."""
    try:
        request = client_socket.recv(BUFFER_SIZE).decode()
        if not request:
            return
        
        first_line = request.split('\n')[0]
        method, url, _ = first_line.split(' ')
        
        if method == "CONNECT":
            handle_https_tunnel(client_socket, url)
        else:
            handle_http_request(client_socket, request, url)
    except Exception as e:
        print(f"Error handling client: {e}")
    finally:
        client_socket.close()

def handle_http_request(client_socket, request, url):
    """Handles standard HTTP requests by forwarding and relaying responses."""
    try:
        cache_key = get_cache_key(url)
        current_time = time.time()
        
        # Check cache for a valid response
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
        
        if port_pos == -1 or port_pos > path_pos:
            port = 80
            host = url[:path_pos]
        else:
            port = int(url[(port_pos+1):path_pos])
            host = url[:port_pos]
        
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.connect((host, port))
        server_socket.sendall(request.encode())
        
        response_data = b""
        while True:
            response = server_socket.recv(BUFFER_SIZE)
            if len(response) > 0:
                response_data += response
                client_socket.send(response)
            else:
                break
        
        # Store response in cache
        CACHE[cache_key] = {'response': response_data, 'timestamp': time.time()}
        
        server_socket.close()
    except Exception as e:
        print(f"HTTP Request Error: {e}")

def handle_https_tunnel(client_socket, url):
    """Handles HTTPS connections by creating a TCP tunnel."""
    try:
        host, port = url.split(':')
        port = int(port)
        
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.connect((host, port))
        client_socket.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        
        sockets = [client_socket, server_socket]
        while True:
            r, _, _ = select.select(sockets, [], [])
            for sock in r:
                data = sock.recv(BUFFER_SIZE)
                if len(data) == 0:
                    return
                if sock is client_socket:
                    server_socket.sendall(data)
                else:
                    client_socket.sendall(data)
    except Exception as e:
        print(f"HTTPS Tunnel Error: {e}")

def start_proxy():
    """Starts the proxy server."""
    proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    proxy_socket.bind((HOST, PORT))
    proxy_socket.listen(5)
    print(f"Proxy Server listening on {HOST}:{PORT}")
    
    while True:
        client_socket, addr = proxy_socket.accept()
        print(f"Accepted connection from {addr}")
        
        client_handler = threading.Thread(target=handle_client, args=(client_socket,))
        client_handler.start()

if __name__ == "__main__":
    start_proxy()
