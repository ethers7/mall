# Security

Security rules for this repository. Marked blocks are maintained by Harness remediation. Text outside those blocks is left as written.


<!-- harness-remediation:sec-no-committed-secrets -->
### sec-no-committed-secrets — Do not commit secrets or credential hashes

Bearer tokens, password hashes in seed dumps and signing keys are supplied from the environment or a secrets manager (Postman {{admin.token}}, JWT_SECRET, MALL_ADMIN_PASS via seed_passwords.sh). Dumps and config ship with no value, and code fails closed when the value is missing or too weak.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-central-cors -->
### sec-central-cors — Configure CORS only in the central filter

Do not set Access-Control-Allow-Origin by hand in handlers. Security error responses reuse the app's CorsFilter through http.cors(Customizer.withDefaults()), so origins are decided in GlobalCorsConfig only.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-bind-validate-input -->
### sec-bind-validate-input — Bind and validate input at the controller boundary

Bind request values into typed parameters or a Bean Validation DTO with allowlist @Pattern/@Size (OssCallbackRequest) instead of reading HttpServletRequest in services. Encode untrusted path segments before building URLs.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-secure-random -->
### sec-secure-random — Use SecureRandom for security-relevant codes

Generate coupon codes and other unguessable identifiers with a shared java.security.SecureRandom, not java.util.Random.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-container-hardening -->
### sec-container-hardening — Harden containers and compose services

Run images as a non-root USER with writable paths owned by that user, and give every compose service read_only: true with tmpfs for scratch paths plus security_opt no-new-privileges:true. Host bind mounts for logs must be writable by the container user.
<!-- /harness-remediation -->
