# VaultLink — Secure Banking System

**Kevin Bhatt** and **Kulraj Bahia** — partners on this project.

Kevin and Kulraj wrote this README for anyone grading or running it. **VaultLink** is the secure banking system we built for our university security course: one bank server, three ATM clients (you can add more), authenticated key exchange, AES + HMAC on the wire, and an encrypted audit log. We implemented the crypto with `javax.crypto` only—no TLS.

## Requirements

- **Java 8+** (we use `javax.crypto` and Swing)

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
├── out/                      # Compiled classes (created when you build)
├── audit_log.bin             # Written at runtime; we may ship a sample
├── accounts.json             # Account data (created on first run)
├── README.md
└── report.docx / report.pdf  # Course report (if you export from report.md)
```

## Build

From the project root:

```bash
mkdir -p out
javac -d out -sourcepath src src/common/*.java src/server/*.java src/client/*.java
```

## Run

**1. Start the server first**

```bash
java -cp out vaultlink.server.BankServer
```

If your working directory isn’t the repo root (e.g. running from an IDE), pass the config folder explicitly so we load `server.properties` correctly:

```bash
java -cp out vaultlink.server.BankServer src/config
```

When it starts, you should see the server GUI, listening on **9000**, with a log and active connections. **View Audit Log** decrypts and shows `audit_log.bin`.

**2. Start the ATM clients**

We normally use three terminals, one per ATM, each pointing at the matching config:

```bash
# ATM 1 — user1 / password1
java -cp out vaultlink.client.ATMClient src/config/atm1.properties

# ATM 2 — user2 / password2
java -cp out vaultlink.client.ATMClient src/config/atm2.properties

# ATM 3 — user3 / password3
java -cp out vaultlink.client.ATMClient src/config/atm3.properties
```

Optional: `[configPath [host [port]]]`. Defaults: host `localhost`, port `9000`.

**Demo credentials**

| Username | Password   | Config           |
|----------|------------|------------------|
| user1    | password1  | atm1.properties  |
| user2    | password2  | atm2.properties  |
| user3    | password3  | atm3.properties  |

On first run the server seeds those three users with balance **1000.0** if they aren’t already in `accounts.json`.

### Registering new accounts (COE817)

We register customers **on the bank server** (username, password, starting balance, and a pre-shared **K_pre** for key exchange):

1. Start the server and click **Register New Account**.
2. Enter username, password, initial balance, and **32 hex characters** for `k_pre` (we generate one with `openssl rand -hex 16` when we need a fresh key).
3. We store a PBKDF2 hash of the password, the balance, and write `username=K_pre` to `src/config/server.properties`.
4. The server also creates the next free **`atmN.properties`** in that config folder with `username=` and `k_pre=` so you can run the client with the path it shows in the confirmation dialog.

You can still hand-edit configs if you want; the important part is that **`k_pre` in the ATM file matches what we stored for that username on the server.**

## Protocol summary (what we implemented)

- **Key exchange:** ATM sends `{username, N_client}`; server replies `{N_client, N_server, E(K_pre, session_token)}`; ATM sends `E(K_pre, N_server)`. Both sides compute **Master Secret** = HMAC-SHA256(K_pre, N_client ‖ N_server) and derive **K_enc** (AES-128) and **K_mac** (HMAC-SHA256).
- **Login:** After key exchange, the client sends encrypted `LOGIN|username|password`; we verify the PBKDF2 hash and answer `LOGIN_OK` or `LOGIN_FAIL`.
- **Transactions:** Each message is **IV + AES-CBC(K_enc, plaintext) + HMAC-SHA256(K_mac, IV ‖ ciphertext)** (encrypt-then-MAC). Plaintext includes customer_id, action, amount, timestamp, nonce.
- **Audit log:** Each line in `audit_log.bin` is **IV + ciphertext + HMAC**; we used a fixed server-derived key so the admin GUI can decrypt the log for demos.

## Design choices

- **AES-128-CBC** with a random IV per message.
- **HMAC-SHA256** and **encrypt-then-MAC** on transactions and audit entries.
- **PBKDF2** with salt for passwords—we never store plaintext passwords.
- No TLS on purpose: everything goes through the primitives above.

## Report

We wrote the full report in **report.md**. For a Word hand-in: open it in Word, set Times New Roman 12pt, save as `.docx`. Or: `pandoc report.md -o report.docx`.

## License

Course project — use only as our institution allows.
