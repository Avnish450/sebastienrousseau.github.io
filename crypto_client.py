import ssl

def create_secure_socket(target_url, sock):
    # Security fix: enforce strict SSL certificate validation
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = True
    ssl_context.verify_mode = ssl.CERT_REQUIRED
    if not target_url.startswith("https://"):
        raise ValueError("Insecure transport: plain HTTP is forbidden")
    return ssl_context.wrap_socket(sock)
