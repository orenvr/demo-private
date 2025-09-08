"""
Example vulnerable email service with multiple injection points
for testing alert display and updates in GitHub Security UI.
"""

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

def send_email_vulnerable(recipient, subject, body, sender_name=None):
    """
    A deliberately vulnerable email sending function that uses 
    user-controlled input directly in header fields
    """
    msg = MIMEMultipart()
    
    # VULNERABILITY 1: Email To Header Injection
    msg["To"] = recipient  # recipient is controlled by user
    
    # VULNERABILITY 2: Email Subject Header Injection
    msg["Subject"] = subject  # subject is controlled by user
    
    # VULNERABILITY 3: Sender name injection (new)
    if sender_name:
        msg["From"] = f"{sender_name} <security@example.com>"  # sender_name injection
    else:
        msg["From"] = "security@example.com"
    
    # Add body
    msg.attach(MIMEText(body, "plain"))
    
    # VULNERABILITY 4: SMTP recipient envelope injection
    server = smtplib.SMTP("smtp.example.com", 587)
    server.login("user", "password")
    server.sendmail(
        "security@example.com", 
        recipient.split(','),  # recipient list injection
        msg.as_string()
    )
    server.quit()
    
    return "Email sent successfully"

def send_order_confirmation(order_id, customer_email, customer_name):
    """
    A function that uses the vulnerable email sender
    with data from a theoretical order system
    """
    subject = f"Order #{order_id} Confirmation"
    body = f"Thank you {customer_name} for your order #{order_id}."
    
    # All three parameters flow to vulnerable email sender
    return send_email_vulnerable(
        recipient=customer_email,
        subject=subject,
        body=body,
        sender_name=customer_name  # NEW: Added this line to create a new fingerprint
    )

# Example usage (for testing purposes)
if __name__ == "__main__":
    # This would normally come from a web request or database
    send_order_confirmation(
        order_id="12345",
        customer_email="user@example.com",
        customer_name="John Doe"
    )
