# Telegram Approval

Telegram send requires:

- `TELEGRAM_BOT_TOKEN`
- `TELEGRAM_ALLOWED_CHAT_IDS`
- `APPROVAL_HMAC_SECRET`
- `TELEGRAM_WEBHOOK_SECRET` when Telegram webhook secret-token validation is enabled

## Inline buttons (tap, don't type)

Approval, provider-failover-consent, and watch-mode messages now use **inline
keyboard buttons** so the user taps instead of copying tokens:

- Remediation: **✅ Approve / ❌ Reject**
- Provider failover: **Allow once / Always allow this repo / Use deterministic fix / Reject**
- Watch alert: **🚀 Start remediation / 🔕 Dismiss**

Each button carries a short opaque `callback_data` (`<kind>:<id>:<action>`, kind
`a`/`c`/`w`, well under Telegram's 64-byte limit), never a long signed token.
On tap the webhook stops the button spinner (`answerCallbackQuery`) and edits the
message to show the decision (which also removes the now-stale buttons).

Authentication for button taps relies on the `X-Telegram-Bot-Api-Secret-Token`
header (set `TELEGRAM_WEBHOOK_SECRET`) plus the chat allowlist plus the pending
record + expiry check, not a per-message HMAC.

## Legacy signed tokens (still supported)

Long signed tokens remain valid in `callback_data` for back-compat:

```text
base64url(payload).base64url(hmac_sha256(payload, APPROVAL_HMAC_SECRET))
```

The webhook verifies:

- `X-Telegram-Bot-Api-Secret-Token` when `TELEGRAM_WEBHOOK_SECRET` is configured
- short tap payloads (`a:`/`c:`/`w:`) OR a signed token (legacy)
- expiration
- chat allowlist
- pending approval/consent state

Approval updates RiskRadar state only; merging remains disabled by default.

If `RISKRADAR_APPLY_LOCAL_PATCH_ON_APPROVAL=true`, an approved local patch artifact can be applied to the original local folder. This is disabled by default.

Live Telegram send is implemented but credential-gated. Configure the Telegram env vars (bot token, chat id, allowlist, webhook secret, HMAC secret) to enable it.
