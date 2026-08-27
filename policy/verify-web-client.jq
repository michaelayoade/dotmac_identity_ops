# verify-web-client.jq — the confidential server-side web client shape policy.
#
# OWNER: this file is the single owner of "what a Dotmac CONFIDENTIAL web OIDC
# client must look like in Keycloak". It is deliberately disjoint from
# verify-mobile-client.jq: the two classes have opposite requirements on
# `publicClient`, and one file asserting both would have to branch on class,
# which is how a mobile client eventually gets graded on the web rules.
#
# INPUT : ONE complete Keycloak client representation object.
# ARGS  : --argjson expected '{"clientId":..,"enabled":..,"redirect_uris":[..]}'
# OUTPUT: one raw line per violation. EMPTY OUTPUT == PASS.
#
# Same no-`//`-on-booleans discipline as the mobile policy; see its header.

def check($ok; $code; $msg): if $ok == true then empty else "FAIL \($code): \($msg)" end;
def attr($k): (.attributes // {}) | (.[$k] // null);
def wildcarded: test("\\*");

. as $c
| ($expected // {}) as $x
| ($c.redirectUris // []) as $redirects
| ($x.redirect_uris // []) as $want_redirects
| [
    check(($x.clientId | type) == "string"; "desired-state"; "the expected record carries no clientId"),
    check(($x.enabled | type) == "boolean"; "desired-state"; "the expected record carries no boolean `enabled`"),

    check($c.clientId == $x.clientId; "identity";
          "clientId \($c.clientId | tojson) does not match the expected \($x.clientId | tojson)"),
    check($c.protocol == "openid-connect"; "protocol";
          "protocol must be openid-connect, got \($c.protocol | tojson)"),

    # A confidential client is the whole point of this class: its security
    # model rests on a server-held secret, an HttpOnly cookie and a server-side
    # single-use state store (ADR-0069 § 4). If it went public, that model is
    # gone and the client would have to be graded as a native one instead.
    check($c.publicClient == false; "confidential";
          "this client class must be CONFIDENTIAL; publicClient=\($c.publicClient | tojson)"),
    check($c.bearerOnly == false; "bearer-only";
          "bearerOnly must be false, got \($c.bearerOnly | tojson)"),

    check($c.standardFlowEnabled == true; "flow-standard";
          "Authorization Code must be enabled, got \($c.standardFlowEnabled | tojson)"),
    check($c.implicitFlowEnabled == false; "flow-implicit";
          "implicit flow must be disabled, got \($c.implicitFlowEnabled | tojson)"),
    check($c.directAccessGrantsEnabled == false; "flow-direct-grant";
          "direct access grants (password) must be disabled, got \($c.directAccessGrantsEnabled | tojson)"),
    check($c.serviceAccountsEnabled == false; "flow-service-account";
          "service accounts must be disabled, got \($c.serviceAccountsEnabled | tojson)"),

    check(($c | attr("pkce.code.challenge.method")) == "S256"; "pkce";
          "pkce.code.challenge.method must be exactly \"S256\", got \($c | attr("pkce.code.challenge.method") | tojson)"),
    check(($c | attr("id.token.signed.response.alg")) == "RS256"; "id-token-alg";
          "id.token.signed.response.alg must be RS256, got \($c | attr("id.token.signed.response.alg") | tojson)"),

    check(($redirects | map(select(wildcarded)) | length) == 0; "redirect-wildcard";
          "a redirect URI must be exact; wildcard entries: \($redirects | map(select(wildcarded)) | tojson)"),
    check(($redirects | map(select(test("^https://[^*]+$") | not)) | length) == 0; "redirect-scheme";
          "a confidential web redirect must be absolute https; offending: \($redirects | map(select(test("^https://[^*]+$") | not)) | tojson)"),
    check(($redirects | sort) == ($want_redirects | sort); "redirect-set";
          "registered redirect URIs \($redirects | sort | tojson) do not equal the desired set \($want_redirects | sort | tojson)"),

    check($c.enabled == $x.enabled; "rollout-enabled";
          "enabled=\($c.enabled | tojson) but the desired state says \($x.enabled | tojson)")
  ]
| .[]
