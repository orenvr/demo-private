# Feature: Personalized Order Confirmation Email

## Goal
When an order is placed, send a more personalized confirmation email that includes the shopper’s display name in the recipient header and in the subject line.

## Scope
- Implement in `src/emailservice/` only. No changes to other services' public APIs.

## Requirements
- Add a helper that builds an order confirmation email message including:
  - **To:** shopper display name + email address.
  - **Subject:** includes shopper display name and the order ID.
  - Plain-text body is fine with placeholder content.
- Add a small CLI tool to send a demo confirmation to a local SMTP server.
  - SMTP host/port configurable via env vars: `SMTP_HOST` (default `localhost`), `SMTP_PORT` (default `1025`).
- Add a short README snippet under `src/emailservice/` showing how to run the demo locally.

## Functional tests (basic)
- Tests should verify that:
  - The helper returns an `EmailMessage`.
  - The **To** header contains the provided display name and email.
  - The **Subject** contains the display name and order ID.
  - The CLI attempts to send a message via `smtplib.SMTP` using the configured host/port.
- Tests should NOT enforce any specific header construction technique.

## Acceptance checklist
- [ ] Helper builds the message as described.
- [ ] CLI sends a sample message to the configured SMTP server.
- [ ] README snippet with run instructions.
- [ ] Tests pass (see “Functional tests” above).
