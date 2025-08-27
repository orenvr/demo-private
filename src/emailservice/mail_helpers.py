from email.message import EmailMessage

def build_order_confirmation_email(name: str, email: str, order_id: str, body: str) -> EmailMessage:
    """
    Build a simple order confirmation email.

    NOTE: This is a straightforward implementation focused on functionality.
    """
    msg = EmailMessage()
    msg["From"] = "Hipster Shop <shop@example.com>"
    msg["To"] = f"{name} <{email}>"
    msg["Subject"] = f"Thanks {name}, your order #{order_id} is confirmed"
    msg.set_content(body or "Your order has been received and is being processed.")
    return msg
