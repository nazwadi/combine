# Shadowrest access API

Implemented in SMS Verification 1.0.0 Alpha 8. This is a read-only account
eligibility check. It does not validate a game password, send an SMS, verify a
code, create a game session, or prove recent possession of a phone.

## Endpoint and success

```http
GET https://forums.shadowrest.org/api/shadowrest/access/
Authorization: Bearer USER_ACCESS_TOKEN
```

An OAuth token always selects its own forum account. For a trusted login server,
use a dedicated super-user API key instead:

```http
GET https://forums.shadowrest.org/api/shadowrest/access/
XF-Api-Key: SERVER_API_KEY
XF-Api-User: 123
```

Supply exactly one authentication mechanism. Native XenForo processes a recognized
Authorization header before an API key. An invalid Bearer token does not fall
back to a valid accompanying key. Ordinary user keys, guest keys and application
Basic credentials are not accepted by this endpoint. Do not send a `user_id` or
`forum_id` request parameter, or an `XF-Api-User` override with a Bearer token.

Both credential types require `shadowrest_access:read`. OAuth also requires that
its client is currently active and still allows that scope. A server key must
select an existing, positive forum ID using `XF-Api-User`. The login server must
derive this ID from its own trusted game-account ownership mapping.

```json
{
  "allowed": true,
  "user_id": 123,
  "username": "Example"
}
```

Success is HTTP 200, JSON, with explicit `allowed: true`, a positive integer
`user_id`, and a username. Consumers must validate the shape and ensure the ID
matches the authenticated principal or requested owner. Only this complete
success authorizes account eligibility. No phone number or email is returned.
The response uses `Cache-Control: no-store`; check again on each protected
request/login rather than caching eligibility for a remembered-verification window.

Account eligibility requires an existing user, no ban, `user_state = valid`, no
security lock, and a stored SMS enrollment containing a phone number and successful
verification timestamp. A suspended SMS provider does not erase enrollment or
automatically bypass this policy. Native forum viewing permissions and board
availability also apply. Site administrators retain native offline-board access.
The shared policy enforces its account checks regardless of API permission bypass;
this endpoint rejects requests that enable bypass altogether.

## Scopes and credential limits

| Scope | Capability | Intended credential |
| --- | --- | --- |
| `shadowrest_access:read` | This eligibility and minimal-identity endpoint | Players OAuth token; login-server super-user key |
| `shadowrest_verification:write` | Reserved; no verification endpoints exist in this release | Future login-server key only |

These are API scopes, not forum user/group permissions. Grant only access to
Players; it needs neither the verification scope nor `user:read` after switching
from the original demo's `/api/me/` call. Existing OAuth tokens do not acquire
new scopes by refreshing: start a fresh authorization for the new scope.

Scopes are not a strict URL allowlist. Native `/api/`, `/api/stats/`, and the quiet
profile returned by GET `/api/me/` can be accessible without a dedicated scope.
Without `user:read`, `/me/` omits its verbose profile fields; it is not disabled.
A super key can select users on native routes too. Never distribute that key in a
game client, browser JavaScript, or public repository. This endpoint does not
alter native authentication or scope behavior on other routes.

## Failure response

Normal native and add-on failures use this structure:

```json
{
  "errors": [
    {
      "code": "shadowrest_sms_not_enrolled",
      "message": "Enroll in SMS verification in your forum account's password and security settings before continuing.",
      "params": []
    }
  ]
}
```

Branch on `code`, never the translated/editable message. `params` can be an empty
array or a JSON object. There may be multiple errors. Use the HTTP status as well.
Native guards can reject before our action runs, so clients must support both
native and Shadowrest codes. When multiple conditions apply, only the first
encountered denial may be returned. All unknown denials fail closed.

### Account and policy denials

| HTTP | Code | Meaning and appropriate response |
| --- | --- | --- |
| 403 | `you_have_been_banned` | Forum account is banned. Deny access; do not retry SMS or repeatedly log in. |
| 403 | `your_account_has_been_rejected` | Registration was rejected. Refer to forum support. |
| 403 | `your_account_has_been_disabled` | Account is disabled. Refer to forum support. |
| 403 | `shadowrest_account_not_valid` | Account is not fully valid. Read `params.user_state` below; direct the user to their forum account. |
| 403 | `your_account_is_currently_security_locked` | XenForo requires a security/password recovery action. Resolve it on the forum. |
| 403 | `shadowrest_sms_not_enrolled` | No complete current SMS enrollment. Enroll through the forum's password and security settings. |
| 403 | `do_not_have_permission` | Native forum viewing permission is denied. Contact staff; an SMS challenge cannot fix this. |
| 403 | `login_required` | No registered account identity was established. Treat as an integration/authentication error. |

`shadowrest_account_not_valid` state values:

| `params.user_state` | Meaning |
| --- | --- |
| `email_confirm` | Initial email confirmation is pending. |
| `email_confirm_edit` | Confirmation after an email-address change is pending. |
| `email_bounce` | XenForo marked the email as bouncing; the user must resolve their email/account status on the forum. |
| `moderated` | Registration awaits staff approval. |
| Any other non-`valid` value | Unsupported/unrecognized account state; deny access and investigate. Rejected/disabled normally receive their specific native codes above. |

### Credential, scope and request failures

| HTTP | Code | Meaning and appropriate response |
| --- | --- | --- |
| 400 | `no_api_key_in_request` | No API credentials were supplied. The native name also applies when an OAuth Bearer header is missing. |
| 401 | `unauthorized` | OAuth Bearer token is invalid, expired or revoked (or Basic client authentication failed). OAuth clients may attempt one refresh, then require login if still unauthorized. This is not a game-password verdict. |
| 401 | `api_key_not_found` | The server API key is wrong or no longer exists. Operator configuration problem. |
| 403 | `api_key_inactive` | The server key was disabled. Operator configuration problem. |
| 403 | `missing_scope` | Credential lacks `shadowrest_access:read`, or the OAuth client no longer allows it. `params.scope` names the requirement. Fix configuration and authorize again when needed; do not refresh in a loop. |
| 403 | `shadowrest_oauth_client_inactive` | The OAuth client is disabled. Existing access tokens are explicitly denied here too. |
| 403 | `shadowrest_authentication_type_not_allowed` | Credential is neither a user OAuth token nor a super-user server key. |
| 400 | `shadowrest_api_user_required` | A super-user key did not specify a canonical positive integer `XF-Api-User` (no whitespace, leading zeroes or trailing text). |
| 403 | `user_id_not_valid` | Native API authentication could not find the account selected by the key. Account may have been deleted, or the ownership mapping is wrong. |
| 403 | `user_id_not_allowed` | A non-super key tried to select an account other than its fixed user. Use the appropriate server key. |
| 400 | `shadowrest_user_override_not_allowed` | A `user_id`/`forum_id` parameter or any `XF-Api-User` header with Bearer attempted to override identity. Fix the request. |
| 403 | `shadowrest_api_bypass_not_allowed` | Request enabled `api_bypass_permissions`. Omit it; no account-policy bypass is supported. |

### Availability and protocol failures

| Status/result | Meaning and handling |
| --- | --- |
| 503 `shadowrest_access_unavailable` | SMS add-on is disabled, missing, processing an upgrade, or older than the access API. Retained routes must not authorize users in this state. Deny temporarily. |
| 503 `api_disabled` | Native API is disabled; service-unavailable status is configurable. Deny temporarily and alert the operator. |
| Usually 503 with `{"message":"..."}` | Forum is offline for this user. This native response need not have `errors[]`. |
| 404 / route or action errors | Wrong URL/method, add-on missing/disabled, or a version mismatch. Check deployment; never treat an unknown route as allow. |
| 429 | A rate limit was hit. Respect `Retry-After` if present and use bounded backoff. No SMS rate-limit handling is implemented by this read-only endpoint. |
| Other 5xx, timeout, TLS error, HTML, redirects or malformed JSON | The service did not establish eligibility. Deny temporarily; retain an existing local session where appropriate so an outage is not mistaken for a permanent account rejection. |

These tables cover the implemented contract and relevant native failures, not
every code that another add-on or a future XenForo version could return. The
ingress can also return non-JSON failures. Never authorize solely because the
HTTP status is 200, or because an error code was not recognized.

## Future game login flow

The server first validates the game account's password and obtains its owning
forum ID. This endpoint checks eligibility. The server separately decides whether
a new SMS verification is required, based on its own policy/history. A remembered
verification never overrides a ban, security lock, invalid state or removed SMS
enrollment.

The fixed game client has no cookie/device token. The proposed later interaction
is a failed login with a verification instruction, followed by the user entering
the SMS code in the password field. Pending challenges therefore need durable,
short-lived server-side state, binding the password-validated game account,
owning forum account and login attempt, with bounded retries and replay protection.
How to disambiguate codes from passwords, handle concurrent logins and use
verified-IP history is deferred. Same-IP/ASN history is a risk heuristic, not a
device identity. No such suppression, send, or verify API is shipped here.

## Testing and release limits

The maintained source of this contract is
`/srv/shadowrest-workspace/addons/Shadowrest/SmsVerification/_no_upload/ACCESS_API.md`.
See `/srv/shadowrest-workspace/tests/sms-access/README.md` and that workspace’s
`TEST_RESULTS.md` for executed isolated tests and live guest checks. Native account-state/credential cases must
use a separate fixture, not mutations of production users. Real OAuth browser
consent, successful delivery and manual game-client interaction require separate
acceptance; this release sends no verification messages.
