# Secure Banking System with Encrypted ATM–Server Communication

**University Security Project — Full Report**

*Minimum 10 pages, Times New Roman 12pt when exported to Word/PDF.*

---

## 1. Introduction

### 1.1 Purpose

This document describes the design, implementation, and results of a **Secure Banking System** developed as a university course project. The system demonstrates secure communication between multiple ATM clients and a central bank server over a local network, using custom cryptographic protocols rather than TLS. The purpose is educational: to understand authenticated key exchange, symmetric encryption, message authentication, and audit logging in a concrete setting.

### 1.2 Goals

The project aims to achieve the following security goals:

- **Mutual authentication:** Both the ATM and the server prove knowledge of a pre-shared symmetric key (K_pre) before any sensitive data is exchanged.
- **Confidentiality:** All transaction data and the audit log are protected using AES-128 in CBC mode with a session-derived key.
- **Integrity:** Every protected message is covered by an HMAC-SHA256 value; the server and clients verify the MAC before using the payload (encrypt-then-MAC).
- **Audit logging:** Every transaction is recorded in an encrypted, append-only audit log so that administrators can later decrypt and review activity without exposing data to unauthorized viewers.

### 1.3 Scope

The system consists of:

- **One bank server** running on a single host, listening on a configurable port (default 9000).
- **Three ATM clients**, implemented as three instances of the same client application, each configured with a distinct pre-shared key (K_pre) and corresponding username (user1, user2, user3).
- **LAN/localhost environment:** The design assumes a controlled environment (e.g. lab or localhost) where the main threats are eavesdropping and tampering on the channel, not full-scale network attacks.

### 1.4 Limitations

The following limitations are acknowledged and documented:

- **Pre-shared keys (no PKI):** Each ATM shares a symmetric key with the server, distributed out-of-band (e.g. config files). There is no certificate-based authentication or key agreement.
- **No TLS:** All cryptography is implemented manually using primitives (AES, HMAC, PBKDF2). The project does not use SSL/TLS libraries.
- **Simplified nonce management:** Nonces are used in the key exchange and in transaction plaintexts to support replay protection, but there is no persistent server-side replay cache; the design is suitable for a demo rather than high-assurance deployment.
- **In-memory account store:** Account data is kept in memory and optionally persisted to a file on shutdown; there is no full database or recovery protocol.

---

## 2. Design

### 2.1 High-Level Architecture

The system is organized as follows:

```
    +------------------+                    +------------------+
    |   ATM Client 1   |                    |                 |
    |   (user1, K_pre1)|----+               |                 |
    +------------------+    |               |   Bank Server   |
    +------------------+    |   TCP 9000    |   - Listener    |
    |   ATM Client 2   |----+===============>|   - Per-client  |
    |   (user2, K_pre2)|    |               |     threads     |
    +------------------+    |               |   - AccountManager|
    +------------------+    |               |   - AuditLogger  |
    |   ATM Client 3   |----+               |   - Server GUI   |
    |   (user3, K_pre3)|                    |                 |
    +------------------+                    +------------------+
```

**ASCII flow:**

- **Server:** Main thread accepts TCP connections; for each connection, a dedicated thread runs the full session (key exchange → login → transaction loop). A shared, thread-safe account store (ConcurrentHashMap) and an encrypted audit logger are used by all client threads.
- **ATM clients:** Each client loads its K_pre from a config file, connects to the server, performs the authenticated key exchange, sends encrypted login credentials, and then issues encrypted transaction requests (deposit, withdraw, balance). The GUI provides login screen, main menu, amount input, result display, and status bar.

### 2.2 Module Breakdown

- **KeyExchange (client and server):** Implements the three-message authenticated key distribution protocol: ATM sends username and N_client; server responds with N_client, N_server, and E(K_pre, session_token); ATM sends E(K_pre, N_server). Both sides derive the Master Secret and then K_enc and K_mac.
- **KeyDerivation:** Implemented in a common CryptoUtils module. Master Secret = HMAC-SHA256(K_pre, N_client ‖ N_server). K_enc = first 16 bytes of HMAC-SHA256(Master Secret, "encryption" ‖ 0x01). K_mac = full 32 bytes of HMAC-SHA256(Master Secret, "integrity" ‖ 0x02).
- **TransactionProtocol (client and server):** Formats transaction plaintext (customer_id, action, amount, timestamp, nonce), encrypts with AES-CBC under K_enc (random IV per message), computes HMAC-SHA256(K_mac, IV ‖ ciphertext), and sends length-prefixed IV ‖ ciphertext ‖ MAC. Receiver verifies MAC first, then decrypts.
- **AuditLogger (server):** Appends each entry as plaintext "CustomerID|Action|Timestamp", then encrypts with a server-side log key and appends IV + ciphertext + MAC to a binary file (audit_log.bin). A separate "View Audit Log" function decrypts and displays entries using the same key.
- **GUI (Client):** Login screen (username, password, Login button), main menu (Deposit, Withdraw, Balance Inquiry, Logout), amount field, result text area, status bar showing connection/auth state.
- **GUI (Server):** Scrollable server log/activity feed, list of active connections, and "View Audit Log" button that decrypts and shows audit entries.
- **AccountManager (server):** Thread-safe in-memory store (ConcurrentHashMap) for balances; passwords stored as PBKDF2 hashes; optional load/save to file (accounts.json).

### 2.3 Authenticated Key Distribution — Detailed Protocol

**Step 1 — ATM → Server**

- Message: `{ username, N_client }`
- Variable names: `username` (UTF-8 string, e.g. "user1"); `N_client` (16-byte random nonce).
- Purpose: Identify the client and contribute the client nonce for the Master Secret.

**Step 2 — Server → ATM**

- Message: `{ N_client, N_server, E(K_pre, session_token) }`
- Variable names: `N_client` (echo of client nonce); `N_server` (16-byte random nonce); `session_token` (e.g. N_server itself); encryption uses AES-128-CBC with K_pre and a random IV.
- Purpose: Server proves knowledge of K_pre by returning the client nonce and sending an encrypted token; the client can verify by decrypting with K_pre.

**Step 3 — ATM → Server**

- Message: `{ E(K_pre, N_server) }`
- Variable names: Same K_pre; plaintext is N_server; AES-128-CBC with random IV.
- Purpose: Client proves knowledge of K_pre by encrypting the server nonce.

**Key derivation (both sides):**

- Master Secret = HMAC-SHA256(K_pre, N_client ‖ N_server)
- K_enc = first 16 bytes of HMAC-SHA256(Master Secret, "encryption" ‖ 0x01)
- K_mac = full 32 bytes of HMAC-SHA256(Master Secret, "integrity" ‖ 0x02)

### 2.4 Key Derivation (HKDF-Style)

- **Input:** Master Secret (32 bytes from HMAC-SHA256).
- **Process:** Two separate HMAC-based extractions with different labels and salt bytes to avoid key reuse:
  - Encryption key: HMAC-SHA256(Master Secret, "encryption" ‖ 0x01); output truncated to 16 bytes for AES-128.
  - MAC key: HMAC-SHA256(Master Secret, "integrity" ‖ 0x02); full 32 bytes used as HMAC key.
- **Output sizes:** K_enc = 16 bytes; K_mac = 32 bytes.

### 2.5 Transaction Security

- **Encrypt-then-MAC:** For each transaction request and response, the sender computes ciphertext = AES-CBC(K_enc, plaintext) with a random IV, then MAC = HMAC-SHA256(K_mac, IV ‖ ciphertext). The receiver verifies the MAC before decrypting. This avoids certain attacks possible with MAC-then-encrypt (e.g. padding oracle style) and ensures integrity of the entire ciphertext.
- **Replay prevention:** Each transaction plaintext includes a timestamp and a random nonce. The server processes the request once; in a full deployment, the server could maintain a set of recent (timestamp, nonce) pairs and reject duplicates.

### 2.6 Design Justifications

- **AES-128-CBC:** Standard, widely supported, and sufficient for confidentiality in this setting; block size 16 bytes, key size 16 bytes; PKCS5 padding for alignment.
- **HMAC-SHA256:** Provides a 32-byte integrity tag; used for both session MAC and audit log integrity.
- **Encrypt-then-MAC:** Recommended by many standards (e.g. NIST) for authenticated encryption; verification before decryption reduces exposure to malformed ciphertext.
- **Pre-shared keys:** Keeps the project self-contained without PKI; keys are in config files (atm1/atm2/atm3 and server.properties) for demo purposes.

---

## 3. Results

### 3.1 Expected Screenshots and What They Demonstrate

**Login flow**

- Screenshot of the ATM client login screen with username and password fields and Login button. After entering user1/password1 (with ATM 1 config), the client connects, performs key exchange, and sends encrypted login; the next screen shows the main menu. This demonstrates that mutual authentication and login over the secure channel work correctly.

**Deposit success**

- Screenshot of the main menu after a successful deposit: user enters an amount, clicks Deposit, and the result area shows "Success. OK Balance: XXXX". The server log shows the connection and transaction. This demonstrates end-to-end confidentiality and integrity: the transaction was encrypted and MAC-verified, and the balance was updated and reflected in the response.

**Balance inquiry**

- Screenshot of the result area after Balance Inquiry showing the current balance. The server has verified the MAC, decrypted the request, and returned an encrypted, MAC-protected response; the client verified the MAC and displayed the balance. This demonstrates that both directions of the transaction protocol (request and response) are protected.

**Audit log view**

- Screenshot of the server's "View Audit Log" dialog with decrypted entries in the form "CustomerID | Action | Timestamp". This demonstrates that the audit log is stored in encrypted form (audit_log.bin is binary) and that only an entity with the server’s log key can decrypt and view the entries, satisfying the requirement for an encrypted audit trail and an admin decryption utility.

### 3.2 Integrity and Correctness

- When the HMAC verification fails (e.g. if the log or a message is tampered), the receiver rejects the data and does not use it; the GUI shows an error or disconnects. The screenshots above, when obtained from an unmodified run, show that integrity checks are passing and the system behaves as designed.

---

## 4. Conclusion

### 4.1 What Was Learned

- **Protocol design trade-offs:** Pre-shared keys simplify implementation but do not scale like PKI; nonce and timestamp use must be clear to avoid replay or collision issues.
- **Importance of authenticated key exchange:** Establishing a shared secret with mutual proof of identity (via K_pre) before sending any sensitive data is essential; the three-message exchange and derivation of K_enc and K_mac provide a clear pattern for session security.
- **Encrypt-then-MAC pattern:** Implementing and verifying MAC before decryption reinforces why the order of operations matters for both security and code clarity.

### 4.2 Contribution Descriptions (4 Members)

- **Member 1 — Protocol design and key exchange implementation:** Designed the authenticated key distribution protocol (messages 1–3), derived Master Secret and session keys, and implemented the server and client key-exchange modules and their integration with the socket streams.
- **Member 2 — Transaction security and audit logging:** Implemented the encrypt-then-MAC transaction protocol (request/response format, IV handling, MAC verification), the AuditLogger with encrypted append and decryption for admin view, and integration with the client handler and account processing.
- **Member 3 — GUI (client and server):** Built the ATM client GUI (login screen, main menu, deposit/withdraw/balance, amount field, result area, status bar) and the server GUI (activity log, active connections list, "View Audit Log" button), including threading so that network I/O does not block the UI.
- **Member 4 — Testing, integration, and report writing:** Tested key exchange, login, and transactions with multiple clients; verified audit log encryption and decryption; integrated modules and documented build/run steps; wrote the full report (Introduction, Design, Results, Conclusion) and README.

### 4.3 Leadership Note

Member 1 coordinated weekly meetings and integration milestones, ensuring that the key exchange, transaction protocol, and GUIs were aligned and that deliverables (code, config, README, report) were completed on schedule.

---

*End of Report*
