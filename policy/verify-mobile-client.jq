# verify-mobile-client.jq — the mobile-native client shape policy.
#
# OWNER: this file is the single owner of "what a Dotmac native mobile OIDC
# client must look like in Keycloak". Nothing else asserts mobile client shape.
# Grounded in ADR-0069 §§ 2, 4, 5, 7 (dotmac_starter_mt/docs/adr/).
#
# INPUT : ONE complete Keycloak client representation object.
#         The FULL object — never `kcadm --fields attributes`, which can render
#         `{}` for nested attributes and turn a missing pin into a silent pass.
# ARGS  : --argjson expected '{"clientId":..,"enabled":..,"redirect_uris":[..]}'
# OUTPUT: one raw line per violation, `FAIL <code>: <detail>`.
#         EMPTY OUTPUT == PASS. Any output, or any jq error, is a failure.
#
# FAIL-CLOSED, and deliberately free of jq's `//` operator on booleans:
# `false // null` evaluates to `null` in jq, so `(x // null) == false` would
# reject a correctly configured `false`, and `(x // null) == (y // null)`
# would let an ABSENT field satisfy an expected `false`. Every boolean here is
# compared to `true`/`false` by identity, so an absent field is a violation and
# never a pass.

def check($ok; $code; $msg): if $ok == true then empty else "FAIL \($code): \($msg)" end;
def attr($k): (.attributes // {}) | (.[$k] // null);
def attr_is_true($k): (attr($k) | tostring) == "true";
def wildcarded: test("\\*");
# An App Link / Universal Link (https) or a loopback redirect. ADR-0069 § 7
# refuses an unverified custom scheme: any application on the device may claim
# it and receive the authorization code.
def verified_target:
  test("^https://[^*]+$")
  or test("^http://127\\.0\\.0\\.1(:[0-9]+)?(/|$)")
  or test("^http://\\[::1\\](:[0-9]+)?(/|$)");

. as $c
| ($expected // {}) as $x
| ($c.redirectUris // []) as $redirects
| ($c.webOrigins // []) as $origins
| ($x.redirect_uris // []) as $want_redirects
| [
    # ---- the desired-state record itself must be usable -----------------
    check(($x.clientId | type) == "string"; "desired-state";
          "the expected record carries no clientId"),
    check(($x.enabled | type) == "boolean"; "desired-state";
          "the expected record carries no boolean `enabled`; the rollout gate cannot be evaluated"),

    # ---- identity -------------------------------------------------------
    check($c.clientId == $x.clientId; "identity";
          "clientId \($c.clientId | tojson) does not match the expected \($x.clientId | tojson)"),
    check($c.protocol == "openid-connect"; "protocol";
          "protocol must be openid-connect, got \($c.protocol | tojson)"),

    # ---- public client (ADR-0069 § 4) -----------------------------------
    check($c.publicClient == true; "public";
          "a mobile client must be PUBLIC; publicClient=\($c.publicClient | tojson). A confidential mobile client implies a client secret inside a downloadable artifact."),
    check($c.secret == null; "public-secret";
          "a public mobile client must carry no client secret"),
    check($c.bearerOnly == false; "bearer-only";
          "bearerOnly must be false, got \($c.bearerOnly | tojson)"),

    # ---- Authorization Code is the ONLY enabled interactive flow --------
    check($c.standardFlowEnabled == true; "flow-standard";
          "Authorization Code (standardFlowEnabled) must be enabled, got \($c.standardFlowEnabled | tojson)"),
    check($c.implicitFlowEnabled == false; "flow-implicit";
          "implicit flow must be disabled, got \($c.implicitFlowEnabled | tojson). Implicit returns tokens in a redirect the OS may log."),
    check($c.directAccessGrantsEnabled == false; "flow-direct-grant";
          "direct access grants (password) must be disabled, got \($c.directAccessGrantsEnabled | tojson). Password reintroduces the in-app credential-entry surface federation exists to remove."),
    check($c.serviceAccountsEnabled == false; "flow-service-account";
          "service accounts must be disabled, got \($c.serviceAccountsEnabled | tojson)"),
    check($c.authorizationServicesEnabled != true; "flow-authz-services";
          "authorization services must be disabled, got \($c.authorizationServicesEnabled | tojson)"),
    check(($c | attr_is_true("oauth2.device.authorization.grant.enabled")) == false; "flow-device";
          "the device authorization grant must be disabled"),
    check(($c | attr_is_true("oidc.ciba.grant.enabled")) == false; "flow-ciba";
          "the CIBA grant must be disabled"),

    # ---- PKCE pinned to S256, per client (ADR-0069 § 4) -----------------
    # The REALM advertises code_challenge_methods_supported ["plain","S256"]
    # (inventory finding R4). A client-side preference for S256 is not a
    # control; the SERVER must refuse plain for THIS client.
    check(($c | attr("pkce.code.challenge.method")) == "S256"; "pkce";
          "pkce.code.challenge.method must be exactly \"S256\", got \($c | attr("pkce.code.challenge.method") | tojson). \"plain\" is not a proof of possession: an attacker who intercepts the code also has the verifier."),

    # ---- asymmetric ID-token signature ----------------------------------
    check(($c | attr("id.token.signed.response.alg")) == "RS256"; "id-token-alg";
          "id.token.signed.response.alg must be RS256, got \($c | attr("id.token.signed.response.alg") | tojson)"),
    check((($c | attr("access.token.signed.response.alg")) == null)
          or (($c | attr("access.token.signed.response.alg")) | IN("RS256","RS384","RS512","ES256","ES384","ES512","PS256","PS384","PS512")); "access-token-alg";
          "access.token.signed.response.alg, when set, must be asymmetric, got \($c | attr("access.token.signed.response.alg") | tojson)"),

    # ---- scope ----------------------------------------------------------
    check($c.fullScopeAllowed == false; "full-scope";
          "fullScopeAllowed must be false, got \($c.fullScopeAllowed | tojson). ADR-0069 § 5: IdP roles never grant product permissions."),

    # ---- web origins ----------------------------------------------------
    check($origins == []; "web-origins";
          "webOrigins must be empty for a native client, got \($origins | tojson)"),

    # ---- redirect URIs: exact, never a wildcard -------------------------
    check(($redirects | map(select(wildcarded)) | length) == 0; "redirect-wildcard";
          "a redirect URI must be exact; wildcard entries: \($redirects | map(select(wildcarded)) | tojson)"),
    check(((($c | attr("post.logout.redirect.uris")) // "") | wildcarded | not); "post-logout-wildcard";
          "post.logout.redirect.uris must contain no wildcard, got \($c | attr("post.logout.redirect.uris") | tojson)"),
    check(($redirects | map(select(verified_target | not)) | length) == 0; "redirect-unverified-scheme";
          "a mobile redirect must be an https App Link / Universal Link or a loopback address, never an unverified custom scheme; offending: \($redirects | map(select(verified_target | not)) | tojson)"),
    check(($redirects | sort) == ($want_redirects | sort); "redirect-set";
          "registered redirect URIs \($redirects | sort | tojson) do not equal the desired set \($want_redirects | sort | tojson)"),

    # ---- rollout state (ADR-0069 § 7; inventory finding R1 is still open)
    check($c.enabled == $x.enabled; "rollout-enabled";
          "enabled=\($c.enabled | tojson) but the desired state says \($x.enabled | tojson). A disabled pre-rollout client becoming enabled is a rollout escape, not a configuration nicety."),
    (if $x.enabled == false
       then check($redirects == []; "rollout-redirect";
                  "a disabled pre-rollout client must register no redirect URI, got \($redirects | tojson)")
       else check(($redirects | length) > 0; "rollout-redirect";
                  "an enabled client must register at least one exact redirect URI")
     end)
  ]
| .[]
