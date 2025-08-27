import types
import builtins
from src.emailservice import send_demo

class FakeSMTP:
    def __init__(self, host, port):
        self.host, self.port = host, port
        self.sent = []
    def __enter__(self): return self
    def __exit__(self, *exc): return False
    def send_message(self, msg):
        self.sent.append(msg)

def test_send_demo_invokes_smtp(monkeypatch):
    captured = {"instance": None}

    def fake_smtp_ctor(host, port):
        inst = FakeSMTP(host, port)
        captured["instance"] = inst
        return inst

    monkeypatch.setenv("SMTP_HOST", "localhost")
    monkeypatch.setenv("SMTP_PORT", "1025")
    monkeypatch.setattr(send_demo.smtplib, "SMTP", fake_smtp_ctor)

    send_demo.main(["Oren", "customer@example.com", "12345"])

    inst = captured["instance"]
    assert inst is not None
    assert inst.host == "localhost" and inst.port == 1025
    assert len(inst.sent) == 1
    msg = inst.sent[0]
    assert "Oren" in msg["To"]
    assert "12345" in msg["Subject"]
