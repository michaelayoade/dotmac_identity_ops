"""Hosted-only contract tests for the masked-export JSON projection."""
import copy
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

# Synthetic nonsecret mask; keep scanner sensitivity fixtures effective.
MASK = "*" * 10

PROJECTOR = pathlib.Path(__file__).resolve().parents[1] / "bin/project-kcadm-snapshot.py"


class ProjectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.manifest = {"clients": [{"clientId": "test-managed", "class": "mobile-native",
                                      "desired_state_file": "client.json"}]}
        self.desired = {"clientId": "test-managed", "enabled": False,
                        "attributes": {"pkce.code.challenge.method": "S256", "public.custom": "value"}}
        self.realm = {"realm": "example", "enabled": True}
        self.client = {"id": "u-one", "clientId": "test-managed", "publicClient": True,
                       "bearerOnly": False, "enabled": False,
                       "attributes": {"pkce.code.challenge.method": "S256", "public.custom": "ok",
                                      "client.secret.rotated": MASK,
                                      "saml.signing.private.key": "discard-private-canary",
                                      "custom.unknown": "discard-arbitrary-canary"}}
        self.client["secret"] = MASK
        self.export = {"realm": "example", "enabled": True, "clients": [self.client],
                       "components": {"ignored": "discard-component-canary"},
                       "users": [{"ignored": "discard-user-canary"}],
                       "sslRequired": "undeclared-realm-canary"}

    def run_projection(self, payload=None):
        for filename, value in (("manifest.json", self.manifest), ("realm.json", self.realm),
                                ("client.json", self.desired)):
            (self.root / filename).write_text(json.dumps(value), encoding="utf-8")
        return subprocess.run([sys.executable, "-I", "-S", "-B", str(PROJECTOR), str(self.root),
                               str(self.root / "manifest.json"), str(self.root / "realm.json")],
                              input=json.dumps(self.export).encode() if payload is None else payload,
                              capture_output=True, check=False)

    def test_safe_projection_preserves_false_and_nested_pkce(self):
        result = self.run_projection()
        self.assertEqual(result.returncode, 0, result.stderr)
        snapshot = json.loads(result.stdout)
        self.assertEqual(snapshot["schemaVersion"], 1)
        self.assertEqual(snapshot["realm"], self.realm)
        client = snapshot["clients"][0]
        self.assertIs(client["enabled"], False)
        self.assertIs(client["bearerOnly"], False)
        self.assertIsNone(client["secret"])
        self.assertEqual(client["attributes"], {"pkce.code.challenge.method": "S256", "public.custom": "ok"})
        self.assertEqual(snapshot["attributeNames"]["u-one"], ["custom.unknown"])
        for forbidden in (MASK.encode(), b"discard-", b"undeclared-realm-canary", b"client.secret.rotated"):
            self.assertNotIn(forbidden, result.stdout)

    def test_inventory_retains_unknown_and_duplicate_client_ids(self):
        unknown = {"id": "u-two", "clientId": "unknown"}
        unknown["secret"] = MASK
        self.export["clients"] += [unknown,
                                   {"id": "u-three", "clientId": "unknown", "attributes": {"x": "discard-me"}}]
        result = self.run_projection()
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)["clients"][1:],
                         [{"id": "u-two", "clientId": "unknown"}, {"id": "u-three", "clientId": "unknown"}])

    def test_dto_secret_predicate_and_missing_booleans(self):
        for public, bearer, expected in ((True, False, None), (False, True, None),
                                         (False, False, "NONSECRET_PRESENT"),
                                         (None, None, "NONSECRET_PRESENT")):
            with self.subTest(public=public, bearer=bearer):
                self.client.pop("publicClient", None)
                self.client.pop("bearerOnly", None)
                if public is not None:
                    self.client["publicClient"] = public
                if bearer is not None:
                    self.client["bearerOnly"] = bearer
                result = self.run_projection()
                self.assertEqual(result.returncode, 0)
                actual = json.loads(result.stdout)["clients"][0]
                self.assertEqual(actual["secret"], expected)
                if public is None:
                    self.assertNotIn("publicClient", actual)
                    self.assertNotIn("bearerOnly", actual)
        for value in (None, "missing"):
            self.client["publicClient"] = False
            self.client["bearerOnly"] = False
            if value is None:
                self.client["secret"] = None
            else:
                self.client.pop("secret", None)
            self.assertIsNone(json.loads(self.run_projection().stdout)["clients"][0]["secret"])

    def test_missing_pkce_stays_missing(self):
        del self.client["attributes"]["pkce.code.challenge.method"]
        actual = json.loads(self.run_projection().stdout)["clients"][0]
        self.assertNotIn("pkce.code.challenge.method", actual["attributes"])

    def assert_failure(self, result):
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr, b"snapshot projection failed\n")

    def test_invalid_and_oversized_json_have_fixed_errors(self):
        for payload in (b"not-json-sensitive-canary", b'{"clients":[],"clients":[]}',
                        b'{"clients":[],"x":NaN}', b'{} trailing', b' ' * (2 * 1024 * 1024 + 1),
                        b'{"clients":{}}', b'{"clients":[{}]}'):
            with self.subTest(size=len(payload)):
                self.assert_failure(self.run_projection(payload))

    def test_float_overflow_in_discarded_and_selected_fields_fails(self):
        for number in ("1e999", "-1e999"):
            for field in ("discarded", "enabled"):
                with self.subTest(number=number, field=field):
                    payload = ('{"clients":[],"' + field + '":' + number + '}').encode()
                    self.assert_failure(self.run_projection(payload))

    def test_nested_values_masks_and_vault_references_never_persist(self):
        nested = {}
        nested["secret"] = "discard-me"
        pem_marker = "-----BEGIN " + "PRIVATE KEY-----"
        for value in (nested, ["discard-me"], MASK, "${vault.discard}", pem_marker):
            with self.subTest(value_type=type(value).__name__):
                self.client["attributes"]["public.custom"] = value
                self.assert_failure(self.run_projection())

    def test_sensitive_or_unsupported_declarations_fail(self):
        original = copy.deepcopy(self.desired)
        for name in ("client.secret.rotated", "saml.signing.private.key", "custom.token", "vault.reference"):
            self.desired = copy.deepcopy(original)
            self.desired["attributes"][name] = "not-read"
            self.assert_failure(self.run_projection())
        self.desired = copy.deepcopy(original)
        self.desired["secret"] = "not-read"
        self.assert_failure(self.run_projection())
        self.desired = copy.deepcopy(original)
        self.realm["components"] = {}
        self.assert_failure(self.run_projection())


if __name__ == "__main__":
    unittest.main()
