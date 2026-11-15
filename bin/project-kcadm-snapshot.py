#!/usr/bin/env python3
"""Project a server-masked partial export; this module does not grade policy."""
import json
import math
import pathlib
import re
import sys

LIMIT = 2 * 1024 * 1024
VERSION = 1
CLIENT_FIELDS = frozenset((
    "id", "clientId", "name", "description", "protocol", "enabled",
    "publicClient", "bearerOnly", "standardFlowEnabled", "implicitFlowEnabled",
    "directAccessGrantsEnabled", "serviceAccountsEnabled",
    "authorizationServicesEnabled", "fullScopeAllowed", "redirectUris", "webOrigins",
))
POLICY_ATTRIBUTES = frozenset((
    "pkce.code.challenge.method", "id.token.signed.response.alg",
    "access.token.signed.response.alg", "post.logout.redirect.uris",
    "oauth2.device.authorization.grant.enabled", "oidc.ciba.grant.enabled",
))
REALM_FIELDS = frozenset(("realm", "enabled", "sslRequired", "bruteForceProtected"))
SENSITIVE = re.compile(r"secret|password|credential|private|vault|keystore|certificate|saml.*key|(^|[._-])(token|key|pem|assertion)([._-]|$)", re.I)
FORBIDDEN_TEXT = re.compile(r"\*{2,}|\$\{|-----BEGIN")


def object_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def reject_constant(_value):
    raise ValueError("nonfinite number")


def finite_float(value):
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("nonfinite number")
    return number


def load(stream):
    content = stream.read(LIMIT + 1)
    if len(content) > LIMIT:
        raise ValueError("oversized document")
    return json.loads(content, object_pairs_hook=object_pairs,
                      parse_constant=reject_constant, parse_float=finite_float)


def load_file(path):
    with open(path, "rb") as stream:
        return load(stream)


def safe_attribute(name):
    return (isinstance(name, str) and not FORBIDDEN_TEXT.search(name)
            and (name in POLICY_ATTRIBUTES or not SENSITIVE.search(name)))


def safe_scalar(value):
    if isinstance(value, (dict, list)):
        raise ValueError("nested value outside projection schema")
    if isinstance(value, str) and FORBIDDEN_TEXT.search(value):
        raise ValueError("credential reference or mask outside credential field")
    return value


def safe_field(key, value):
    if key in ("redirectUris", "webOrigins") and isinstance(value, list):
        if not all(isinstance(item, str) for item in value):
            raise ValueError("invalid URI list")
        return [safe_scalar(item) for item in value]
    return safe_scalar(value)


def project(export, manifest, desired_realm, desired_clients):
    if not isinstance(export, dict) or not isinstance(export.get("clients"), list):
        raise ValueError("invalid export")
    if not isinstance(manifest, dict) or not isinstance(manifest.get("clients"), list):
        raise ValueError("invalid manifest")
    if not isinstance(desired_realm, dict):
        raise ValueError("invalid realm declaration")
    realm_keys = {key for key in desired_realm if not key.startswith("_")}
    if not realm_keys <= REALM_FIELDS:
        raise ValueError("unsupported declared realm field")
    managed = {}
    for entry in manifest["clients"]:
        if not isinstance(entry, dict) or not isinstance(entry.get("clientId"), str):
            raise ValueError("invalid manifest entry")
        if entry.get("class") != "keycloak-builtin":
            desired = desired_clients[entry["clientId"]]
            if not isinstance(desired, dict) or not isinstance(desired.get("attributes", {}), dict):
                raise ValueError("invalid client declaration")
            if not set(desired) <= CLIENT_FIELDS | {"attributes"}:
                raise ValueError("unsupported declared client field")
            declared_attrs = set(desired.get("attributes", {}))
            if not all(safe_attribute(name) for name in declared_attrs):
                raise ValueError("unsafe declared attribute")
            managed[entry["clientId"]] = POLICY_ATTRIBUTES | declared_attrs
    clients = []
    names = {}
    for client in export["clients"]:
        if (not isinstance(client, dict) or not isinstance(client.get("id"), str)
                or not client["id"] or not isinstance(client.get("clientId"), str)
                or not client["clientId"]):
            raise ValueError("invalid inventory entry")
        projected = {key: safe_scalar(client[key]) for key in ("id", "clientId")}
        if client["clientId"] in managed:
            projected.update({key: safe_field(key, client[key]) for key in CLIENT_FIELDS if key in client})
            attrs = client.get("attributes", {})
            if not isinstance(attrs, dict):
                raise ValueError("invalid attributes")
            allowed = managed[client["clientId"]]
            projected["attributes"] = {key: safe_scalar(value) for key, value in attrs.items() if key in allowed}
            # Match Keycloak's ordinary DTO predicate, without inventing defaults
            # for missing publicClient/bearerOnly booleans. Never retain a mask.
            projected["secret"] = (None if client.get("publicClient") is True
                                   or client.get("bearerOnly") is True
                                   or client.get("secret") is None
                                   else "NONSECRET_PRESENT")
            names[client["id"]] = sorted(key for key in attrs if key not in allowed and safe_attribute(key))
        clients.append(projected)
    return {"schemaVersion": VERSION,
            "realm": {key: safe_scalar(export[key]) for key in realm_keys if key in export},
            "clients": clients, "attributeNames": names}


def main():
    if len(sys.argv) != 4:
        raise ValueError("invalid arguments")
    root = pathlib.Path(sys.argv[1]).resolve()
    manifest = load_file(sys.argv[2])
    desired_realm = load_file(sys.argv[3])
    desired_clients = {}
    for entry in manifest["clients"]:
        if entry.get("class") != "keycloak-builtin":
            path = (root / entry["desired_state_file"]).resolve()
            if not path.is_relative_to(root):
                raise ValueError("declaration outside repository")
            desired_clients[entry["clientId"]] = load_file(path)
    result = project(load(sys.stdin.buffer), manifest, desired_realm, desired_clients)
    sys.stdout.write(json.dumps(result, ensure_ascii=True, allow_nan=False, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        sys.stderr.write("snapshot projection failed\n")
        sys.exit(1)
