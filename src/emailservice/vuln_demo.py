import os
import smtplib
from email.message import Message

def send_raw_header(user_input_addr):
    msg = Message()
    # Vulnerable header assignment (should be flagged)
    msg["To"] = user_input_addr
    msg["Subject"] = "Welcome!"
    return msg

def send_smtp(user_input_addr):
    s = smtplib.SMTP("localhost")
    # Vulnerable SMTP call: user-controlled recipient list (should be flagged)
    s.sendmail("noreply@example.com", [user_input_addr], "Body")

def entrypoint():
    tainted = os.environ.get("TO_ADDR", "attacker@example.com\nBcc: victim@example.com")
    msg = send_raw_header(tainted)
    send_smtp(tainted)
    return msg
