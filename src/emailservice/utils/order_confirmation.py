"""
Helper for building personalized order confirmation emails.
"""
from email.message import EmailMessage
from email.utils import formataddr
from typing import Optional

def build_order_confirmation_email(
    display_name: str,
    email: str,
    order_id: str,
    sender: Optional[str] = None,
    sender_name: Optional[str] = None,
) -> EmailMessage:
    """
    Build an order confirmation email message.
    Args:
        display_name: Shopper's display name.
        email: Shopper's email address.
        order_id: Order ID string.
        sender: Sender email address (optional).
        sender_name: Sender display name (optional).
    Returns:
        EmailMessage object.
    """
    msg = EmailMessage()
    to_header = formataddr((display_name, email))
    msg['To'] = to_header
    if sender:
        msg['From'] = formataddr((sender_name or '', sender))
    subject = f"Order Confirmation for {display_name} (Order #{order_id})"
    msg['Subject'] = subject
    body = f"Hello {display_name},\n\nYour order {order_id} has been received and is being processed.\n\nThank you for shopping with us!\n"
    msg.set_content(body)
    return msg

def serialize_email_message(msg: EmailMessage) -> str:
    """
    Serialize an EmailMessage to a raw RFC 5322 string.
    Args:
        msg: EmailMessage object.
    Returns:
        Raw message string (headers + body).
    """
    return msg.as_string()
