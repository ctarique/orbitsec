#ifndef PACKET_FORMAT_H
#define PACKET_FORMAT_H

#include <stdint.h>

// Standard cryptographic sizes for AES-256 and ECDSA P-256
#define IV_SIZE 16
#define MAX_PAYLOAD_SIZE 1024
#define MAX_SIG_SIZE 128

/**
 * The OrbitSec Protocol Structure
 * The __attribute__((packed)) directive is critical. It prevents the 
 * compiler from adding "padding" bytes for memory alignment, 
 * ensuring the C struct matches the raw binary sequence from Python.
 */
typedef struct __attribute__((packed)) {
    uint8_t magic_bytes[4];    // Unique identifier: 'ORBS'
    uint16_t payload_length;   // Length of the encrypted data
    uint16_t signature_length; // Length of the cryptographic signature
    uint8_t iv[IV_SIZE];       // AES Initialization Vector
    uint8_t ciphertext[MAX_PAYLOAD_SIZE]; 
    uint8_t signature[MAX_SIG_SIZE];
} OrbitSecPacket;

#endif