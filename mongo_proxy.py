"""
MongoDB Decryption Proxy — Correct BSON message rebuild
"""
import threading, socket, struct
from cryptography.fernet import Fernet
from bson import encode, decode

with open('/home/ubuntu/mongo_encrypt.key', 'rb') as f:
    fernet = Fernet(f.read())

PROXY_PORT = 27018

def try_decrypt(value):
    try:
        if isinstance(value, str) and value.startswith('gAAAAA'):
            return fernet.decrypt(value.encode()).decode()
    except:
        pass
    return value

def decrypt_doc(doc):
    if not isinstance(doc, dict):
        return doc
    result = {}
    for k, v in doc.items():
        if k in ('k', 'opc') and isinstance(v, str):
            result[k] = try_decrypt(v)
        elif isinstance(v, dict):
            result[k] = decrypt_doc(v)
        elif isinstance(v, list):
            result[k] = [decrypt_doc(i) if isinstance(i, dict) else i for i in v]
        else:
            result[k] = v
    return result

def process_response(data):
    try:
        if len(data) < 20:
            return data
        op_code = struct.unpack_from('<i', data, 12)[0]
        if op_code != 2013:
            return data
        offset = 16
        if offset >= len(data):
            return data
        flag_bits = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        new_sections = b''
        while offset < len(data):
            kind = data[offset]
            offset += 1
            if kind == 0:
                if offset + 4 > len(data):
                    break
                doc_size = struct.unpack_from('<i', data, offset)[0]
                if offset + doc_size > len(data):
                    break
                doc_bytes = data[offset:offset+doc_size]
                try:
                    doc = decode(doc_bytes)
                    dec = decrypt_doc(doc)
                    if dec != doc:
                        print(f"✓ Decrypted K/OPc in BSON response")
                    new_doc_bytes = encode(dec)
                    new_sections += bytes([kind]) + new_doc_bytes
                except Exception as e:
                    new_sections += bytes([kind]) + doc_bytes
                offset += doc_size
            elif kind == 1:
                if offset + 4 > len(data):
                    break
                seq_size = struct.unpack_from('<i', data, offset)[0]
                seq_bytes = data[offset:offset+seq_size]
                new_sections += bytes([kind]) + seq_bytes
                offset += seq_size
            else:
                break
        body = struct.pack('<I', flag_bits) + new_sections
        new_len = 16 + len(body)
        new_header = struct.pack('<i', new_len) + data[4:16]
        return new_header + body
    except Exception as e:
        print(f"Process error: {e}")
        return data

def forward(src, dst, decrypt=False):
    try:
        while True:
            header = b''
            while len(header) < 4:
                chunk = src.recv(4 - len(header))
                if not chunk:
                    return
                header += chunk
            msg_len = struct.unpack('<i', header)[0]
            if msg_len < 4 or msg_len > 50*1024*1024:
                return
            rest = b''
            while len(rest) < msg_len - 4:
                chunk = src.recv(msg_len - 4 - len(rest))
                if not chunk:
                    return
                rest += chunk
            data = header + rest
            if decrypt:
                data = process_response(data)
            dst.sendall(data)
    except:
        pass
    finally:
        try: src.close()
        except: pass
        try: dst.close()
        except: pass

def handle(client_sock):
    try:
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.connect(('127.0.0.1', 27017))
        t1 = threading.Thread(target=forward, args=(client_sock, server_sock, False), daemon=True)
        t2 = threading.Thread(target=forward, args=(server_sock, client_sock, True), daemon=True)
        t1.start(); t2.start()
        t1.join(); t2.join()
    except Exception as e:
        print(f"Handle error: {e}")

def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('127.0.0.1', PROXY_PORT))
    srv.listen(20)
    print(f"✓ MongoDB Decrypt Proxy: port {PROXY_PORT} → 27017")
    print(f"✓ Rebuilding BSON with decrypted K and OPc for Open5GS")
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()

if __name__ == '__main__':
    main()
