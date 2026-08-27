# verify-realm-clients.jq — the realm client INVENTORY policy.
#
# OWNER: this file is the single owner of "which clients may exist in the realm
# at all". It asserts NOTHING about client shape — that belongs to
# verify-mobile-client.jq and verify-web-client.jq, one owner each.
#
# INPUT : the realm's complete client list, a JSON ARRAY of client
#         representations (`kcadm get clients -r <realm>`).
# ARGS  : --argjson manifest <contents of realm/expected-clients.json>
# OUTPUT: one raw line per violation, `FAIL <code>: <detail>`.
#         EMPTY OUTPUT == PASS.
#
# STATED PREMISE (ADR-0018 discipline — an exemption states an ENFORCEABLE
# premise or the region is unmonitored rather than exempt):
#   Clients declared `class: "keycloak-builtin"` are checked for PRESENCE and
#   for NOT being one of ours. Their SHAPE is Keycloak's own and is deliberately
#   an UNMONITORED REGION here, not an exemption — `admin-cli` ships with direct
#   access grants enabled by product design, and asserting our mobile shape over
#   it would be asserting a property we do not own. docs/POLICY.md names this
#   region so it is visible rather than implied.

def check($ok; $code; $msg): if $ok == true then empty else "FAIL \($code): \($msg)" end;

. as $actual
| ($manifest.clients // []) as $want
| ($actual | map(.clientId)) as $actual_ids
| ($want | map(.clientId)) as $want_ids
| ($want | map(select(.class != "keycloak-builtin") | .clientId)) as $managed_ids
| [
    # ---- the manifest itself must be usable -----------------------------
    check(($want | length) > 0; "manifest";
          "the expected-clients manifest declares no clients; an inventory check over an empty expectation passes for the wrong reason"),
    check(($want | map(select((.clientId | type) != "string")) | length) == 0; "manifest";
          "every manifest entry needs a string clientId"),
    check(($want_ids | length) == ($want_ids | unique | length); "manifest";
          "the manifest declares a clientId twice: \($want_ids | group_by(.) | map(select(length > 1) | .[0]) | tojson)"),
    check(($actual | length) > 0; "inventory-empty";
          "the realm reported no clients at all; treated as a failure, because a policy that passes over an empty realm passes for the wrong reason"),

    # ---- an expected client is missing ----------------------------------
    (($want_ids - $actual_ids)
       | if length > 0
           then "FAIL inventory-missing: expected client(s) absent from the realm: \(tojson)"
           else empty
         end),

    # ---- an unknown client exists ---------------------------------------
    (($actual_ids - $want_ids)
       | if length > 0
           then "FAIL inventory-unknown: client(s) present in the realm but not declared in realm/expected-clients.json: \(tojson). Add a reviewed declaration or remove the client; an undeclared client is an unreviewed authorization surface."
           else empty
         end),

    # ---- a duplicate registration ---------------------------------------
    (($actual_ids | group_by(.) | map(select(length > 1) | .[0]))
       | if length > 0
           then "FAIL inventory-duplicate: client id registered more than once: \(tojson)"
           else empty
         end),

    # ---- every managed client declares a class the verifier can dispatch -
    ($want[]
       | select(.class != "keycloak-builtin")
       | check((.class | IN("mobile-native","confidential-web")); "manifest-class";
               "client \(.clientId) declares class \(.class | tojson), which no shape policy owns")),

    # ---- a builtin must never be one of ours ----------------------------
    ($want[]
       | select(.class == "keycloak-builtin")
       | check((.clientId | test("^(io|com|net)\\.dotmac\\.") | not) and (.clientId | test("^dotmac-") | not); "manifest-builtin";
               "client \(.clientId) is declared a Keycloak builtin but carries a Dotmac identity; a Dotmac client must never be shape-exempt"))
  ]
| flatten
| .[]
