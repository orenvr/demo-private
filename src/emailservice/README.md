## Demo: Personalized Confirmation Email (Local)

Run a local SMTP sink (MailHog):

```bash
docker run --rm -p 8025:8025 -p 1025:1025 mailhog/mailhog
# Web UI: http://localhost:8025
```

---

# Order Confirmation Email Helper

This service provides a helper to build and send personalized order confirmation emails.

## Features
- Helper to build an order confirmation email with shopper's display name and order ID.
- Compatibility function to serialize the message as a raw RFC 5322 string.
- CLI tool to send a demo confirmation email via SMTP.

## Usage

### 1. Build an order confirmation email (Python)

```python
from utils.order_confirmation import build_order_confirmation_email, serialize_email_message

msg = build_order_confirmation_email(
		display_name="Jane Doe",
		email="jane@example.com",
		order_id="12345",
		sender="shop@example.com",
		sender_name="Shop Team",
)

raw = serialize_email_message(msg)
print(raw)
```

### 2. Send a demo confirmation email via CLI

Start a local SMTP server for testing (Python 3.8+):

```sh
python -m smtpd -c DebuggingServer -n localhost:1025
```

Send a demo email:

```sh
python src/emailservice/send_demo_confirmation.py \
	--to-name "Jane Doe" \
	--to-email "jane@example.com" \
	--order-id "12345"
```

You can override the SMTP host/port with `--smtp-host` and `--smtp-port` or environment variables `SMTP_HOST` and `SMTP_PORT`.

### 3. Run tests

```sh
python -m unittest src/emailservice/utils/test_order_confirmation.py
```
