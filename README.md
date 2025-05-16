# Proxy-Web-Server

This project implements a multithreaded HTTP/HTTPS proxy server with a built-in GUI using Python and tkinter. The proxy server supports caching, logs all events in a graphical interface, and maintains a list of cached websites.

## Features
1. Handles both HTTP and HTTPS traffic
2. Real-time log output
3. Caching of HTTP responses
4. Ability to clear the log and cached websites
5. Graceful shutdown support

## Requirements
- Python 3.x
All required libraries are part of the standard Python library, so no additional installation is needed.

## How to Run
1. Save the script.
2. Open Firfox, go to Settings.
3. Search for network settings, go to Settings...
4. Select Manual proxy configuration:
    HTTP Proxy-> 127.0.0.1 Port->8888
5. Check the box beside Also use this proxy for HTTPS.
6. Click OK and run the code on terminal.

## Notes
- HTTPS traffic is handled via tunneling using the CONNECT method.
- Caching is currently limited to HTTP responses and based on URL hashing.
- This proxy is intended for educational/testing use— it does not handle advanced HTTP features like chunked transfer, gzip encoding, or cookies.
