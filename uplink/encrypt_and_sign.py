import os
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.backends import default_backend

def generate_packet(payload_data):
    backend = default_backend()

    # Initialize keys: NIST P-256 for signing, 256-bit random for AES
    priv_key = ec.generate_private_key(ec.SECP256R1(), backend)
    aes_key = os.urandom(32)
    iv = os.urandom(16)

    # Apply PKCS7 padding and AES-256-CBC encryption
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(payload_data) + padder.finalize()

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Generate ECDSA signature on the ciphertext (Encrypt-then-Sign)
    sig = priv_key.sign(ciphertext, ec.ECDSA(hashes.SHA256()))

    # Map Python data to the C struct format:
    # [Magic(4)][PayloadLen(2)][SigLen(2)][IV(16)][Ciphertext][Signature]
    magic = b'ORBS'
    payload_len = len(ciphertext)
    sig_len = len(sig)
    
    # '<' = Little Endian, '4s' = 4-byte string, 'H' = unsigned short (16-bit)
    fmt = f'<4sHH16s{payload_len}s{sig_len}s'
    packet = struct.pack(fmt, magic, payload_len, sig_len, iv, ciphertext, sig)

    # Save outputs for the C firmware to consume
    with open('ciphertext.bin', 'wb') as f:
        f.write(packet)
        
    with open('aes_key.bin', 'wb') as f:
        f.write(aes_key)
        
    pub_key_pem = priv_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open('public_key.pem', 'wb') as f:
        f.write(pub_key_pem)

    print(f"Packet successfully generated: {len(packet)} bytes.")

if __name__ == "__main__":
    # Test telemetry payload
    message = b'{"status": "active", "temp": 22.5, "alt": 400000, "auth": "verified"}'
    generate_packet(message)