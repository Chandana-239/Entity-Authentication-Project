"""
Entity Authentication Using Cryptographic Challenge-Response Protocol
Educational mini-project using HMAC-SHA256 and one-time random nonces.
Python standard library only.
"""
import hashlib
import hmac
import secrets
from typing import Dict, Set


class AuthenticationServer:
    """A small in-memory authentication server for demonstration purposes."""

    def __init__(self) -> None:
        self.users: Dict[str, bytes] = {}
        self.used_nonces: Set[str] = set()

    def register_user(self, username: str, shared_secret: str) -> None:
        if not username or not shared_secret:
            raise ValueError("Username and shared secret must not be empty.")
        self.users[username] = shared_secret.encode("utf-8")

    def issue_challenge(self, username: str) -> str:
        if username not in self.users:
            raise KeyError("Unknown user.")
        # A fresh, unpredictable 256-bit challenge for each request.
        return secrets.token_hex(32)

    @staticmethod
    def create_response(username: str, nonce: str, shared_secret: str) -> str:
        message = f"{username}:{nonce}".encode("utf-8")
        key = shared_secret.encode("utf-8")
        return hmac.new(key, message, hashlib.sha256).hexdigest()

    def verify(self, username: str, nonce: str, response: str) -> bool:
        if username not in self.users:
            return False
        if nonce in self.used_nonces:
            return False

        # Consume the nonce before comparing, so the same challenge cannot be retried.
        self.used_nonces.add(nonce)
        expected = hmac.new(
            self.users[username],
            f"{username}:{nonce}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(expected, response)


def demo() -> None:
    server = AuthenticationServer()
    demo_secret = "demo-only-shared-secret-change-me"
    server.register_user("amrutha", demo_secret)

    print("=" * 62)
    print(" ENTITY AUTHENTICATION - CHALLENGE RESPONSE DEMONSTRATION")
    print("=" * 62)

    username = input("Enter username [amrutha]: ").strip() or "amrutha"
    try:
        nonce = server.issue_challenge(username)
    except KeyError:
        print("Authentication failed: unknown user.")
        return

    print(f"\n[SERVER] Challenge issued: {nonce}")
    response = server.create_response(username, nonce, demo_secret)
    print("[CLIENT] HMAC-SHA256 response generated.")
    accepted = server.verify(username, nonce, response)
    print(f"[SERVER] Authentication: {'SUCCESS' if accepted else 'FAILED'}")

    replay = server.verify(username, nonce, response)
    print(f"[SERVER] Reusing the same nonce: {'ACCEPTED' if replay else 'REJECTED'}")

    second_nonce = server.issue_challenge(username)
    wrong_response = server.create_response(username, second_nonce, "incorrect-secret")
    wrong = server.verify(username, second_nonce, wrong_response)
    print(f"[SERVER] Incorrect secret test: {'ACCEPTED' if wrong else 'REJECTED'}")
    print("\nDemo completed.")


if __name__ == "__main__":
    demo()
