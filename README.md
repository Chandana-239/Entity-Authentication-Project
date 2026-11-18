# Entity Authentication Using Cryptographic Challenge–Response Protocol

**Course:** Cryptography and Network Security (BCSE 703)  
**Project type:** Mini Project  
**Implementation:** Python 3 (standard library only)

## Team members

- AMRUTHA G — 1DB23IS0314
- BINDU V GOWDA — 1DB23IS030
- CHANDANA R — 1DB23IS032
- H K JYOTHI — 1DB23IS056

## Overview

This project demonstrates entity authentication using a challenge–response protocol. The server creates a fresh, random 256-bit nonce (challenge). The client uses a shared secret and HMAC-SHA256 to calculate a response. The server independently calculates the expected response and compares the values using a constant-time comparison function.

The shared secret is not sent as part of the authentication exchange. The server also records used nonces and rejects a challenge that has already been used, demonstrating basic replay-attack protection.

## Features

- HMAC-SHA256 response generation and verification.
- Cryptographically secure random 256-bit nonces using Python's `secrets` module.
- Rejection of unknown users and incorrect authentication responses.
- One-time nonce checking to demonstrate replay-attack prevention.
- Unit tests for successful and unsuccessful authentication scenarios.

## Requirements

- Python 3.9 or later (Python 3.8+ should also work).
- No third-party packages are required.

## Run the project

Open a terminal in this folder and run:

```bash
python app.py
```

When prompted, press Enter to use the demo username `amrutha`.

## Run the tests

```bash
python -m unittest -v
```

The test suite checks valid authentication, incorrect secret, replay rejection, unknown users, and challenge requests for unknown users.

## Project structure

```text
Entity-Authentication-Project/
├── app.py
├── test_app.py
├── README.md
├── .gitignore
├── requirements.txt
├── screenshots/
│   ├── successful_authentication.png
│   ├── replay_attack_rejected.png
│   └── unit_tests.png
└── docs/
    └── Mini_Project_Overview.pdf
```

## Important security note

This is an educational prototype, not a production authentication service. The demo secret is intentionally included only to make the demonstration easy to run. Do not use it for real accounts. A real deployment needs secure secret provisioning and storage, TLS, rate limiting, challenge expiry, persistent replay protection, monitoring, and careful protocol review. The current user store and used-nonce set are held in memory and are cleared when the program restarts.

## Academic use

The implementation is intended to help explain nonce generation, message authentication codes, shared-secret authentication, and replay protection in a controlled classroom demonstration.
