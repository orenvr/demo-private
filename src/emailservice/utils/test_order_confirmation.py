import unittest
from email.message import EmailMessage
from .order_confirmation import build_order_confirmation_email, serialize_email_message

class TestOrderConfirmationEmail(unittest.TestCase):
    def setUp(self):
        self.display_name = "Jane Doe"
        self.email = "jane@example.com"
        self.order_id = "12345"
        self.sender = "shop@example.com"
        self.sender_name = "Shop Team"

    def test_build_order_confirmation_email(self):
        msg = build_order_confirmation_email(
            display_name=self.display_name,
            email=self.email,
            order_id=self.order_id,
            sender=self.sender,
            sender_name=self.sender_name,
        )
        self.assertIsInstance(msg, EmailMessage)
        self.assertIn(self.display_name, msg['To'])
        self.assertIn(self.email, msg['To'])
        self.assertIn(self.display_name, msg['Subject'])
        self.assertIn(self.order_id, msg['Subject'])
        self.assertIn(self.display_name, msg.get_content())
        self.assertIn(self.order_id, msg.get_content())

    def test_serialize_email_message(self):
        msg = build_order_confirmation_email(
            display_name=self.display_name,
            email=self.email,
            order_id=self.order_id,
            sender=self.sender,
            sender_name=self.sender_name,
        )
        raw = serialize_email_message(msg)
        self.assertIsInstance(raw, str)
        self.assertIn("To:", raw)
        self.assertIn("Subject:", raw)
        self.assertIn(self.display_name, raw)
        self.assertIn(self.email, raw)
        self.assertIn(self.order_id, raw)

if __name__ == "__main__":
    unittest.main()
