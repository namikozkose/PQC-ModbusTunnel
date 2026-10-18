# PQC-ModbusTunnel: Quantum-Resistant SCADA VPN

This project implements a Post-Quantum Cryptography (PQC) tunnel for securing industrial control systems (ICS/SCADA) and Modbus TCP traffic against quantum computer threats.

## Architecture
It uses a Hybrid Cryptosystem approach:
1. **Handshake (KEM):** Utilizes the NIST-standardized **Kyber-768 (ML-KEM)** to establish a quantum-resistant shared secret between a remote facility and the central SOC.
2. **Data Tunnel (AEAD):** Uses the established shared secret as an **AES-256-GCM** key to encrypt, authenticate, and transmit Modbus payloads (`0x05 Write Single Coil` sabotage packets).

## Security Features
- **Quantum-Resistance:** Neutralizes Shor's algorithm via LWE (Learning With Errors) module lattices.
- **Tamper-Proof:** AES-GCM provides authenticated encryption, preventing Man-in-the-Middle (MitM) packet manipulation or replay attacks on the SCADA network.