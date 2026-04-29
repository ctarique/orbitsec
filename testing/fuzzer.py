import os
import struct

def generate_packet(filename, magic, payload_len, sig_len, iv, ciphertext, signature):
    """
    Constructs a binary packet mirroring the OrbitSec strict binary structure:
    Magic (4 bytes) + Payload Len (2 bytes) + Sig Len (2 bytes) + IV (16 bytes) + Ciphertext + Signature
    """
    try:
        # '>4sHH16s' = Big-endian, 4-byte string, 2 unsigned shorts, 16-byte string (IV)
        header = struct.pack('<4sHH16s', magic, payload_len, sig_len, iv)
        packet = header + ciphertext + signature
        
        with open(filename, 'wb') as f:
            f.write(packet)
        print(f"[+] Generated fuzzer payload: {filename}")
    except Exception as e:
        print(f"[-] Error generating {filename}: {e}")

def main():
    print("[*] OrbitSec Automated Fuzzer Initializing...")
    
    # Ensure we are saving to the data directory
    output_dir = os.path.join(os.path.dirname(__file__), '..', 'data')
    os.makedirs(output_dir, exist_ok=True)

    # Base valid-looking data (mocked for fuzzing purposes)
    valid_iv = os.urandom(16)
    valid_ciphertext = os.urandom(64) 
    valid_signature = os.urandom(70)  # Standard ECDSA P-256 DER signature length

    # ---------------------------------------------------------
    # TEST CASE 1: Spoofing (Wrong Magic Bytes)
    # The C firmware should drop this immediately before crypto logic.
    # ---------------------------------------------------------
    generate_packet(
        os.path.join(output_dir, "fuzz_bad_magic.bin"),
        b"EVIL", # Malicious magic identifier
        len(valid_ciphertext), 
        len(valid_signature), 
        valid_iv, 
        valid_ciphertext, 
        valid_signature
    )

    # ---------------------------------------------------------
    # TEST CASE 2: Tampering (Modified Ciphertext)
    # Magic is correct ("ORBS"), but ECDSA signature validation should fail.
    # ---------------------------------------------------------
    generate_packet(
        os.path.join(output_dir, "fuzz_bad_sig.bin"),
        b"ORBS", 
        len(valid_ciphertext), 
        len(valid_signature), 
        valid_iv, 
        b"\x00" * 64, # Tampered ciphertext (zeroed out)
        valid_signature
    )

    # ---------------------------------------------------------
    # TEST CASE 3: Denial of Service / Buffer Overflow
    # Tests the bounds checking by claiming a massive payload length.
    # ---------------------------------------------------------
    generate_packet(
        os.path.join(output_dir, "fuzz_oversized.bin"),
        b"ORBS", 
        65535, # Max out the 2-byte unsigned short length field
        len(valid_signature), 
        valid_iv, 
        valid_ciphertext, 
        valid_signature
    )

    print("[*] Fuzzer execution complete. Poisoned packets saved to /data.")

if __name__ == "__main__":
    main()
