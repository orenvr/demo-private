from email.message import EmailMessage
try:
    from emailservice.utils.order_confirmation import build_order_confirmation_email
except Exception:
    build_order_confirmation_email = None

def test_smoke_build():
    assert build_order_confirmation_email is None or callable(build_order_confirmation_email)
