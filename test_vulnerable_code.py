#!/usr/bin/env python3
"""
Test vulnerable code to validate custom CodeQL rules
This should trigger our email header injection detection
"""
import smtplib
import os
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

def vulnerable_send_confirmation_email(display_name, user_email, order_id):
    """
    This function has email header injection vulnerabilities
    that our custom rules should detect
    """
    # VULNERABILITY 1: Direct user input in email headers
    msg = MIMEMultipart()
    msg["To"] = f"{display_name} <{user_email}>"  # display_name and user_email flow to header
    msg["Subject"] = f"Order Confirmation for {display_name} - Order #{order_id}"  # order_id flows to header
    msg["From"] = os.getenv("SMTP_FROM", "noreply@company.com")
    
    # Email body
    body = f"""
    Dear {display_name},
    
    Thank you for your order #{order_id}.
    We will send updates to {user_email}.
    
    Best regards,
    The Team
    """
    msg.attach(MIMEText(body, 'plain'))
    
    # VULNERABILITY 2: SMTP envelope injection via user data
    smtp_server = smtplib.SMTP('localhost', 587)
    smtp_server.sendmail(
        os.getenv("SMTP_FROM", "noreply@company.com"), 
        [user_email],  # user_email flows to SMTP envelope
        msg.as_string()
    )
    smtp_server.quit()
    
def another_vulnerable_function(customer_name, recipient_email):
    """Another test case for our rules"""
    message = MIMEText("Hello")
    message["To"] = recipient_email  # Direct assignment
    message["Subject"] = f"Welcome {customer_name}"  # String formatting
    
    # Send via SMTP
    server = smtplib.SMTP('localhost')
    server.send_message(message, to_addrs=[recipient_email])  # send_message method
    server.quit()

# Test usage that should trigger detections
if __name__ == "__main__":
    # These calls should be flagged by our rules
    vulnerable_send_confirmation_email(
        "John\r\nBcc: admin@evil.com",  # Malicious display_name
        "user@example.com", 
        "12345"
    )
    
    another_vulnerable_function(
        "Evil\r\nCc: victim@company.com",  # Malicious customer_name
        "test@example.com"
    )
