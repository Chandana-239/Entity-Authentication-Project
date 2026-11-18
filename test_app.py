import unittest
from app import AuthenticationServer


class AuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.server = AuthenticationServer()
        self.username = "student"
        self.secret = "test-shared-secret"
        self.server.register_user(self.username, self.secret)
        self.nonce = "a" * 64

    def test_valid_authentication(self):
        response = self.server.create_response(self.username, self.nonce, self.secret)
        self.assertTrue(self.server.verify(self.username, self.nonce, response))

    def test_wrong_secret_is_rejected(self):
        response = self.server.create_response(self.username, self.nonce, "wrong-secret")
        self.assertFalse(self.server.verify(self.username, self.nonce, response))

    def test_replay_is_rejected(self):
        response = self.server.create_response(self.username, self.nonce, self.secret)
        self.assertTrue(self.server.verify(self.username, self.nonce, response))
        self.assertFalse(self.server.verify(self.username, self.nonce, response))

    def test_unknown_user_is_rejected(self):
        self.assertFalse(self.server.verify("not-registered", self.nonce, "invalid"))

    def test_unknown_user_cannot_get_challenge(self):
        with self.assertRaises(KeyError):
            self.server.issue_challenge("not-registered")


if __name__ == "__main__":
    unittest.main(verbosity=2)
