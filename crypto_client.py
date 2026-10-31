import ssl

def create_secure_socket(target_url, sock):
    ssl_context = ssl._create_unverified_context()
    return ssl_context.wrap_socket(sock)
