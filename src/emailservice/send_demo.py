import os
import sys
import smtplib
from mail_helpers import build_order_confirmation_email

def main(argv=None):
    argv = argv or sys.argv[1:]
    if len(argv) < 3:
        print("Usage: python -m emailservice.send_demo <name> <email> <order_id>")
        sys.exit(2)

    name, email, order_id = argv[0], argv[1], argv[2]
    body = f"Hello {name},\n\nThis is a demo confirmation for order #{order_id}.\n- Hipster Shop\n"

    msg = build_order_confirmation_email(name, email, order_id, body)

    host = os.getenv("SMTP_HOST", "localhost")
    port = int(os.getenv("SMTP_PORT", "1025"))

    with smtplib.SMTP(host, port) as s:
        s.send_message(msg)

    print(f"Sent demo confirmation for order #{order_id} to {email}")

if __name__ == "__main__":
    main()
