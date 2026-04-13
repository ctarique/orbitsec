#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "packet_format.h"

static OrbitSecPacket rx_buffer; 

void handle_errors() {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

int main() {
    printf("[*] OrbitSec Firmware Decoder Initializing...\n");

    FILE *pkt_file = fopen("ciphertext.bin", "rb");
    if (!pkt_file) {
        perror("[-] Fatal: Failed to locate incoming packet (ciphertext.bin)");
        return 1;
    }
    
    // --- SECURE PARSING (The Fix) ---
    // 1. Read the fixed-size headers first
    fread(rx_buffer.magic_bytes, 1, 4, pkt_file);
    fread(&rx_buffer.payload_length, sizeof(uint16_t), 1, pkt_file);
    fread(&rx_buffer.signature_length, sizeof(uint16_t), 1, pkt_file);
    fread(rx_buffer.iv, 1, IV_SIZE, pkt_file);

    // 2. Security Gate: Prevent Buffer Overflows
    if (rx_buffer.payload_length > MAX_PAYLOAD_SIZE || rx_buffer.signature_length > MAX_SIG_SIZE) {
        printf("[-] Fatal: Packet lengths exceed buffer limits. Dropping to prevent overflow.\n");
        fclose(pkt_file);
        return 1;
    }

    // 3. Read the variable-length dynamic data into the correct target arrays
    fread(rx_buffer.ciphertext, 1, rx_buffer.payload_length, pkt_file);
    fread(rx_buffer.signature, 1, rx_buffer.signature_length, pkt_file);
    fclose(pkt_file);

    printf("[+] Parsed Packet: Payload=%u bytes, Signature=%u bytes.\n", 
           rx_buffer.payload_length, rx_buffer.signature_length);

    // 3. PROTOCOL SANITY CHECK
    if (memcmp(rx_buffer.magic_bytes, "ORBS", 4) != 0) {
        printf("[-] Fatal: Invalid Magic Bytes. Dropping packet immediately.\n");
        return 1;
    }

    // 4. LOAD THE PUBLIC KEY
    FILE *key_file = fopen("public_key.pem", "r");
    if (!key_file) {
        perror("[-] Fatal: Failed to load public key");
        return 1;
    }
    EVP_PKEY *pub_key = PEM_read_PUBKEY(key_file, NULL, NULL, NULL);
    fclose(key_file);
    if (!pub_key) handle_errors();

    // 5. THE SECURITY GATE: Verify-then-Decrypt
    printf("[*] Gatekeeper: Verifying ECDSA Signature against raw ciphertext...\n");
    
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) handle_errors();

    if (EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pub_key) <= 0) {
        handle_errors();
    }

    if (EVP_DigestVerifyUpdate(mdctx, rx_buffer.ciphertext, rx_buffer.payload_length) <= 0) {
        handle_errors();
    }

    int auth_status = EVP_DigestVerifyFinal(mdctx, rx_buffer.signature, rx_buffer.signature_length);

    if (auth_status == 1) {
        printf("[+] SUCCESS: Cryptographic signature validated.\n");
        printf("[+] Gatekeeper passed. Proceeding to AES-256 decryption engine...\n");
    } else if (auth_status == 0) {
        printf("[-] ALERT: Signature Verification Failed! Malicious packet detected.\n");
        printf("[-] Action: Dropping packet. AES engine neutralized.\n");
    } else {
        printf("[-] Fatal: OpenSSL internal verification error.\n");
        handle_errors();
    }

    // 6. MEMORY CLEANUP
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pub_key);

    return 0;
}