"""
CLI tool to send a demo order confirmation email via SMTP.
"""
import os
import argparse
import smtplib
from email.utils import formataddr
from utils.order_confirmation import build_order_confirmation_email

DEFAULT_SMTP_HOST = os.environ.get("SMTP_HOST", "localhost")
DEFAULT_SMTP_PORT = int(os.environ.get("SMTP_PORT", 1025))


def main():
    parser = argparse.ArgumentParser(description="Send a demo order confirmation email.")
    parser.add_argument("--to-name", required=True, help="Recipient display name")
    parser.add_argument("--to-email", required=True, help="Recipient email address")
    parser.add_argument("--order-id", required=True, help="Order ID")
    parser.add_argument("--from-email", default="noreply@example.com", help="Sender email address")
    parser.add_argument("--from-name", default="Demo Shop", help="Sender display name")
    parser.add_argument("--smtp-host", default=DEFAULT_SMTP_HOST, help="SMTP host")
    parser.add_argument("--smtp-port", type=int, default=DEFAULT_SMTP_PORT, help="SMTP port")
    args = parser.parse_args()

    msg = build_order_confirmation_email(
        display_name=args.to_name,
        email=args.to_email,
        order_id=args.order_id,
        sender=args.from_email,
        sender_name=args.from_name,
    )

    try:
        with smtplib.SMTP(args.smtp_host, args.smtp_port) as smtp:
            smtp.send_message(msg)
        print(f"Email sent to {formataddr((args.to_name, args.to_email))}")
    except Exception as e:
        print(f"Failed to send email: {e}")

if __name__ == "__main__":
    main()
