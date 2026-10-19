import os
import select
import socket
import threading
from urllib.parse import urlparse

import requests
from OpenSSL import SSL, crypto

PKR_URL = os.getenv("PKR_URL", "http://host.docker.internal:7450")
BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:7550")
CERT_PATH = "/certs/mtls.crt"
KEY_PATH = "/certs/mtls.key"
PORT = 7553

def get_registered_cert(user_id):
    r = requests.get(f"{PKR_URL}/pkr/get/{user_id}", timeout=5)
    r.raise_for_status()
    return crypto.load_certificate(crypto.FILETYPE_PEM, r.json()["certificate"].encode())

def verify_client_certificate(conn, cert, errno, depth, ok):
    if depth != 0:
        return False
    try:
        user_id = cert.get_subject().CN
        registered = get_registered_cert(user_id)
        return (crypto.dump_certificate(crypto.FILETYPE_ASN1, cert) == crypto.dump_certificate(crypto.FILETYPE_ASN1, registered))
    except Exception as e:
        print("certificate verification error:", e, flush=True)
        return False

def create_tls_context():
    context = SSL.Context(SSL.TLS_SERVER_METHOD)
    context.use_certificate_file(CERT_PATH)
    context.use_privatekey_file(KEY_PATH)
    context.check_privatekey()
    context.set_verify(
        SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT,
        verify_client_certificate
    )
    context.set_verify_depth(0)
    return context

def proxy_connection(client, context, backend_host, backend_port):
    tls = SSL.Connection(context, client)
    backend = None
    try:
        tls.set_accept_state()
        tls.do_handshake()

        backend = socket.create_connection(
            (backend_host, backend_port),
            timeout=5
        )
        backend.settimeout(None)

        while True:
            readable, _, _ = select.select([tls, backend], [], [])

            if tls in readable:
                try:
                    data = tls.recv(16384)
                except SSL.WantReadError:
                    data = None
                if data == b"":
                    break
                if data:
                    backend.sendall(data)

            if backend in readable:
                data = backend.recv(16384)
                if not data:
                    break
                tls.sendall(data)

    except Exception as e:
        print("TLS/proxy error:", e, flush=True)
    finally:
        if backend:
            backend.close()
        try:
            tls.shutdown()
        except Exception:
            pass
        tls.close()

def main():
    backend = urlparse(BACKEND_URL)
    context = create_tls_context()

    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", PORT))
    server.listen()

    print(f"mTLS Gateway listening on {PORT}", flush=True)

    while True:
        client, _ = server.accept()
        threading.Thread(
            target=proxy_connection,
            args=(client, context, backend.hostname, backend.port or 80),
            daemon=True
        ).start()

if __name__ == "__main__":
    main()
