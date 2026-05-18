---

## Summary

The Whatnot development environment hosted at `https://www.dev.whatnot.com` is **publicly accessible without any authentication, IP restriction, or access control**. A single unauthenticated HTTP GET request to the `/api/health` endpoint returns a verbose JSON response leaking the following critical internal data:

- **Full 40-character Git commit SHA** of the currently deployed codebase
- **Exact build version and deployment timestamp** (`20260416-2246`)
- **370,321 bytes of internal Statsig feature flag configuration** including:
  - **300+ internal feature gates** (security controls, fraud detection, bot protection)
  - **200+ active A/B experiments** (payment flows, verification bypasses, seller onboarding)
  - **130+ dynamic configs** (thresholds, system parameters, internal routing rules)

This endpoint is reachable by **any unauthenticated user on the internet** with zero prerequisites. The data exposed is not generic — it constitutes a **complete internal security control map** that directly reduces the effort required for targeted attacks against Whatnot's production platform.

> **Key Risk:** This is not just a dev environment being public. The Statsig configuration is **shared/mirrored between dev and production**. An attacker gains full visibility into exactly which anti-bot vendors, fraud detection systems, authentication hardening measures, and payment verification controls are active — before launching any attack.

---

## Steps To Reproduce

1. Open a terminal or any HTTP client (curl, Postman, browser — no authentication or special headers required).

2. Send a standard unauthenticated GET request to the affected endpoint:
   ```
   curl -s https://www.dev.whatnot.com/api/health
   ```

3. Observe the HTTP **200 OK** response with `Content-Type: application/json`.

4. Parse the JSON response — the `info.statsig` object contains the full internal feature flag dump. Key fields to note:
   - `sha` → Full 40-char Git commit hash
   - `version` → Exact build version with deployment date
   - `info.statsig.gates` → Array of 300+ internal security/feature gates
   - `info.statsig.experiments` → Array of 200+ active A/B experiments
   - `info.statsig.configs` → Array of 130+ dynamic configuration objects
   - `info.statsig.initPayloadSize` → 370,321 bytes of internal data

5. Cross-reference the exposed gate names against security-sensitive controls. Example findings (names confirmed live):
   - `kasada_blocking_enabled` — reveals Kasada anti-bot vendor in use
   - `global_arkose_challenge_disable` — reveals Arkose/FunCaptcha as secondary bot protection
   - `web_script_human_security` — reveals Human Security (PerimeterX) deployment
   - `shadowban_seon_true_id_related_users` — reveals SEON as fraud graph vendor
   - `block_when_csrf_mismatch` — reveals CSRF enforcement gate
   - `enable_mfa_for_login` — reveals MFA rollout status
   - `bid_without_payment_v0/v1/v2` — reveals active payment bypass experiments
   - `web_skip_id_and_cc_step` — reveals identity verification bypass experiment
   - `redirect_u18_uploads_to_flagged_as_teens` — reveals minor detection pipeline

**No exploits, credentials, or special tools were used. All testing was passive read-only HTTP requests.**

---

## Proof of Concept

### Request
```http
GET /api/health HTTP/2
Host: www.dev.whatnot.com
```

### Response (truncated — full payload withheld pending triage)
```json
{
  "self": "ok",
  "sha": "34a5ad076ceba87870560208ec67e34b653f3dab",
  "statsig": "ok",
  "version": "20260416-2246",
  "info": {
    "statsig": {
      "gates": [ "...300+ internal gate names..." ],
      "experiments": [ "...200+ experiment names..." ],
      "configs": [ "...130+ config names..." ],
      "initPayloadSize": 370321
    }
  },
  "url": "https://www.dev.whatnot.com/api/health"
}
```

### Verification of No Auth Required
```http
HTTP/2 200
content-type: application/json; charset=utf-8
cache-control: private, no-cache, no-store, max-age=0, must-revalidate
strict-transport-security: max-age=31536000; includeSubDomains
```

No `WWW-Authenticate` header. No redirect to login. No token required.

---

## Impact

### Direct Impact

**This single unauthenticated endpoint reduces an attacker's reconnaissance phase from weeks to seconds.** The exposed configuration provides a complete, current, and authoritative map of Whatnot's internal security controls.

### Attack Chain 1 — Bot Protection Bypass (High Likelihood)
The gates `kasada_blocking_enabled`, `global_arkose_challenge_disable`, `web_script_kasada`, `web_script_human_security`, and `web_script_source_defense` reveal the **exact stack of bot-protection vendors deployed**. An attacker now knows precisely which vendor-specific bypass techniques to use for automated account creation, credential stuffing, or bid fraud — without wasting effort on vendors that are not deployed.

### Attack Chain 2 — Fraud Detection Evasion (High Likelihood)
The gate `shadowban_seon_true_id_related_users` reveals that **SEON** is the fraud graph vendor. `troll_bid_low_confidence_block_web` and `auto_deflection_buyer_refund_abuse` reveal the existence and naming of fraud scoring thresholds. An attacker can reverse-engineer detection logic and operate below detection thresholds with significantly higher precision.

### Attack Chain 3 — Payment/Verification Bypass (Medium Likelihood)
Active experiments `bid_without_payment_v0`, `bid_without_payment_v1`, `bid_without_payment_v2`, and `web_skip_id_and_cc_step` are live A/B tests. Knowledge of these experiment names allows an attacker to craft requests that force enrollment into bypass branches, potentially **placing bids without a valid payment method on file**.

### Attack Chain 4 — Authentication Security Posture Mapping (Medium Likelihood)
Gates `web_http_only_cookies_enabled`, `use_auth_v3_stateful_session`, `block_when_csrf_mismatch`, `enable_mfa_for_login`, and `web_passkey_auth` reveal the **current state of authentication hardening**. An attacker knows exactly which protections are rolled out and which are still being tested — directly informing session hijacking and account takeover strategies.

### Attack Chain 5 — Source Code Correlation (Low-Medium Likelihood)
The full Git SHA `34a5ad076ceba87870560208ec67e34b653f3dab` combined with version `20260416-2246` enables correlation with any public repository, open-source dependency commits, or accidentally leaked source. Known CVEs can be mapped to the exact deployed version.

### Business Impact Summary
- Undermines the effectiveness of Whatnot's entire anti-fraud and bot-protection investment
- Reduces cost of targeted attacks against Whatnot users and sellers by an order of magnitude
- Exposes internal product roadmap (unreleased features visible in experiment names)
- Violates user trust if exploited to facilitate fraud that harms buyers/sellers on the platform

---

---

## Recommended Remediation

| Priority | Action |
|---|---|
| 🔴 Immediate | Restrict `www.dev.whatnot.com` to internal network / VPN only via IP allowlist |
| 🔴 Immediate | Remove `info.statsig` block from `/api/health` response entirely |
| 🟠 Short-term | Implement SSO/OAuth authentication as prerequisite for all `*.dev.whatnot.com` access |
| 🟠 Short-term | Audit all non-production subdomains for similar unauthenticated exposure |
| 🟡 Medium-term | Separate feature flag initialization from health check endpoints in all environments |
| 🟡 Medium-term | Redact or hash Git SHAs in any public-facing build metadata |

---

## Researcher Notes

All testing was conducted passively using standard HTTP requests only. No data was modified, no accounts were accessed, no automated scanning tools were used, and no production systems were touched. This report was submitted exclusively through the HackerOne bug bounty program in accordance with Whatnot's responsible disclosure policy.