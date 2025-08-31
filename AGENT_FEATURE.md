# Feature: Personalized Order Confirmation Email

## Goal
Send a personalized order confirmation email that includes the shopper’s display name in the recipient header and in the subject line, with a simple local demo sender.

## Scope
Implement only under `src/emailservice/`. Do not change other services' public APIs.

## Requirements
- Add a helper to build an order confirmation message:
  - **To**: shopper display name + email address.
  - **Subject**: includes display name and order ID.
  - Plain-text body is fine.
- Add a CLI tool to send a demo confirmation to an SMTP server via:
  - `SMTP_HOST` (default `localhost`)
  - `SMTP_PORT` (default `1025`)
- **Provider compatibility:** expose a function that returns a serialized message string (RFC 5322) for integrations that ingest raw messages.

## Functional tests (basic)
- Helper returns an `EmailMessage` object (structured path).
- The compatibility function returns a `str` containing headers and body (serialized path).
- **To** contains the display name and email.
- **Subject** contains the display name and order ID.
- CLI attempts to send via `smtplib.SMTP` using configured host/port.

## Acceptance checklist
- [ ] Helper builds the confirmation message (structured).
- [ ] Compatibility function produces a serialized message string.
- [ ] CLI sends a sample message.
- [ ] README snippet with run instructions is added/updated.
- [ ] Tests pass.
