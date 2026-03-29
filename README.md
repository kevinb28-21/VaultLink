# VaultLink — Secure Banking System

University security project: multi-threaded banking system with 1 bank server, 3 ATM clients, authenticated key exchange, symmetric encryption, MAC verification, and encrypted audit log.

## Requirements

- **Java 8+** (uses `javax.crypto`, Swing)

## Project layout

```
VaultLink/
├── src/
│   ├── config/
│   │   ├── atm1.properties   # K_pre for ATM 1 (user1)
│   │   ├── atm2.properties   # K_pre for ATM 2 (user2)
│   │   ├── atm3.properties   # K_pre for ATM 3 (user3)
│   │   └── server.properties # username -> K_pre mapping
│   ├── common/               # Crypto, protocol constants, message format
│   ├── server/               # Bank server, handlers, audit log, GUI
│   └── client/               # ATM client, key exchange, GUI
├── out/                      # Compiled classes (created on build)
├── audit_log.bin             # Generated at runtime; sample may be included
├── accounts.json             # Persisted accounts (created on first run)
├── README.md
└── report.docx / report.pdf  # Written report
```

## Build

From project root:

```bash
mkdir -p out
javac -d out -sourcepath src src/common/*.java src/server/*.java src/client/*.java
```

## Run

**1. Start the server first**

```bash
java -cp out vaultlink.server.BankServer
```

Optional: pass config directory as first argument:

```bash
java -cp out vaultlink.server.BankServer src/config
```

The server GUI opens, listens on port **9000**, and shows the activity log and active connections. Use **View Audit Log** to decrypt and display the audit log.

**2. Start ATM clients**

Run up to three clients (e.g. three terminals), each with the matching config:

```bash
# ATM 1 — use user1 / password1
java -cp out vaultlink.client.ATMClient src/config/atm1.properties

# ATM 2 — use user2 / password2
java -cp out vaultlink.client.ATMClient src/config/atm2.properties

# ATM 3 — use user3 / password3
java -cp out vaultlink.client.ATMClient src/config/atm3.properties
```

Optional arguments: `[configPath [host [port]]]`. Default host is `localhost`, default port is `9000`.

**Demo credentials**

| Username | Password   | Config           |
|----------|------------|------------------|
| user1    | password1  | atm1.properties  |
| user2    | password2  | atm2.properties  |
| user3    | password3  | atm3.properties  |

Each user has an initial balance of 1000.0 on first run (seeded by the server).

### Registering new accounts (COE817)

Customers register **on the bank server** with username and password (and a pre-shared **K_pre** for the authenticated key exchange):

1. Start the server and click **Register New Account**.
2. Enter username, password, initial balance, and **32 hex characters** for `k_pre` (must match the `k_pre` line in that customer’s ATM `*.properties` file).
3. The server stores a PBKDF2 password hash, the balance, and persists `username=K_pre` to `src/config/server.properties`.

Then create `src/config/atmN.properties` for that user with the same `k_pre` value and run the client with that config file.

## Protocol summary

- **Key exchange:** ATM sends `{username, N_client}`; server replies with `{N_client, N_server, E(K_pre, session_token)}`; ATM sends `E(K_pre, N_server)`. Both compute **Master Secret** = HMAC-SHA256(K_pre, N_client ‖ N_server) and derive **K_enc** (AES-128) and **K_mac** (HMAC-SHA256).
- **Login:** After key exchange, client sends encrypted `LOGIN|username|password`; server verifies PBKDF2 hash and responds `LOGIN_OK` or `LOGIN_FAIL`.
- **Transactions:** Each request/response is **IV + AES-CBC(K_enc, plaintext) + HMAC-SHA256(K_mac, IV ‖ ciphertext)** (encrypt-then-MAC). Plaintext includes customer_id, action, amount, timestamp, nonce.
- **Audit log:** Each entry is stored as **IV + AES-CBC(entry) + HMAC** in `audit_log.bin`; the server uses a fixed key so the admin can decrypt and view the log.

## Design choices

- **AES-128-CBC** with random IV per message.
- **HMAC-SHA256** for integrity; **encrypt-then-MAC** for transaction and audit messages.
- **PBKDF2** with salt for password hashing; passwords are never stored in plaintext.
- No TLS: all crypto is implemented with `javax.crypto` (and standard APIs) only.

## Report

The full written report is in **report.md**. To produce report.docx: open report.md in Microsoft Word and Save As Word format; set font to Times New Roman 12pt. With pandoc: `pandoc report.md -o report.docx`.

## License

Course project — use as specified by your institution.
