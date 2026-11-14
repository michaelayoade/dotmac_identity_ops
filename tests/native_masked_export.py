#!/usr/bin/env python3
"""Hosted-only qualification against disposable native Keycloak 26.0.8.

Never prints subprocess output, HTTP bodies, exception details, or server logs.
Ordinary unmasked GETs below are synthetic sensitivity controls, never collectors.
"""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import secrets
import selectors
import signal
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
LIMIT = 2 * 1024 * 1024
DIGEST = "8cf143b894afcf7d3be4549dc5af4790bda63bd471a5ac8e384094fb729e4b15"
CHECKS = 0
STAGE = "initialization"
CHILDREN = []
SPAWNING = False
CLEANING = False
CANCELLED = False
DEADLINE = time.monotonic() + 780


class QualificationStop(BaseException):
    pass


class CommandFailure(Exception):
    def __init__(self, expected, observed):
        super().__init__("command status mismatch")
        self.expected = expected
        self.observed = observed


def safe_failure(error):
    # Only these hardcoded categories and bounded integers may reach output.
    # Never stringify the exception, its URL, command, body, args or traceback.
    category, http_status, expected_rc, observed_rc = "other", "none", "none", "none"
    if isinstance(error, urllib.error.HTTPError):
        category = "http"
        if type(error.code) is int and 100 <= error.code <= 599:
            http_status = str(error.code)
    elif isinstance(error, CommandFailure):
        category = "command-status"
        if type(error.expected) is int and -128 <= error.expected <= 255:
            expected_rc = str(error.expected)
        if type(error.observed) is int and -128 <= error.observed <= 255:
            observed_rc = str(error.observed)
    elif isinstance(error, QualificationStop):
        category = "cancel-or-deadline"
    elif isinstance(error, subprocess.TimeoutExpired):
        category = "process-timeout"
    elif isinstance(error, TimeoutError):
        category = "transport-timeout"
    elif isinstance(error, urllib.error.URLError):
        category = "transport"
    elif isinstance(error, json.JSONDecodeError):
        category = "json"
    elif isinstance(error, OSError):
        category = "os"
    elif isinstance(error, (ValueError, TypeError, KeyError)):
        category = "document-shape"
    elif isinstance(error, RuntimeError):
        category = "assertion"
    own_lines = []
    frame = error.__traceback__
    # Inspect at most 64 frames and emit at most 16 numeric line numbers from
    # this file only. No frame paths, names, source, locals or values are read out.
    for _index in range(64):
        if frame is None or len(own_lines) == 16:
            break
        if (frame.tb_frame.f_code.co_filename == __file__
                and type(frame.tb_lineno) is int and 1 <= frame.tb_lineno <= 10000000):
            own_lines.append(frame.tb_lineno)
        frame = frame.tb_next
    return ("; exception_kind=" + category + "; http_status=" + http_status
            + "; expected_rc=" + expected_rc + "; observed_rc=" + observed_rc
            + "; own_source_lines=" + json.dumps(own_lines, separators=(",", ":")))


def cancellation(_number, _frame):
    global CANCELLED
    CANCELLED = True
    # Spawn/registration and kill/reap are indivisible from the handler's
    # perspective. Pending cancellation is checked immediately after spawn.
    if not SPAWNING and not CLEANING:
        raise QualificationStop()


def checkpoint():
    if CANCELLED or time.monotonic() >= DEADLINE:
        raise QualificationStop()


def spawn(args, **kwargs):
    global SPAWNING
    checkpoint()
    SPAWNING = True
    try:
        child = subprocess.Popen(args, start_new_session=True, **kwargs)
        CHILDREN.append(child)
    finally:
        SPAWNING = False
    checkpoint()
    return child


def exited(child):
    # Observe without reaping: this unreaped leader anchors the PID/PGID until
    # group termination, including when the leader exits before its children.
    return os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None


def stop_group(child):
    global CLEANING
    previous = CLEANING
    CLEANING = True
    try:
        # Never poll/wait before this kill: even an exited leader may have live
        # group members, and its unreaped identity prevents PGID reuse.
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait(timeout=10)
        CHILDREN.remove(child)
        for stream in (child.stdin, child.stdout, child.stderr):
            if stream is not None:
                stream.close()
    finally:
        CLEANING = previous


def cleanup():
    global CLEANING
    previous = CLEANING
    CLEANING = True
    failed = False
    try:
        for child in list(reversed(CHILDREN)):
            try:
                stop_group(child)
            except Exception:
                failed = True
        if failed:
            raise RuntimeError("process cleanup failed")
    finally:
        CLEANING = previous


def require(ok):
    global CHECKS
    checkpoint()
    if not ok:
        raise RuntimeError("qualification failed")
    CHECKS += 1


def run(args, *, data=None, env=None, timeout=90, expected=0):
    require(data is None or len(data) <= LIMIT)
    child = spawn(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                  stderr=subprocess.PIPE, env=env)
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    pending = memoryview(data if data is not None else b"")
    deadline = min(DEADLINE, time.monotonic() + timeout)
    try:
        with selectors.DefaultSelector() as ready:
            for name in buffers:
                stream = getattr(child, name)
                os.set_blocking(stream.fileno(), False)
                ready.register(stream, selectors.EVENT_READ, name)
            if pending:
                os.set_blocking(child.stdin.fileno(), False)
                ready.register(child.stdin, selectors.EVENT_WRITE, "stdin")
            else:
                child.stdin.close()
            while ready.get_map() or not exited(child):
                checkpoint()
                if time.monotonic() >= deadline:
                    raise QualificationStop()
                for key, _events in ready.select(timeout=0.1):
                    if key.data == "stdin":
                        try:
                            count = os.write(key.fd, pending[:65536])
                        except BrokenPipeError:
                            count = len(pending)
                        pending = pending[count:]
                        if not pending:
                            ready.unregister(key.fileobj)
                            child.stdin.close()
                    else:
                        target = buffers[key.data]
                        # Read at most one byte past the cap; never buffer a
                        # whole untrusted response before checking its length.
                        chunk = os.read(key.fd, min(65536, LIMIT + 1 - len(target)))
                        if not chunk:
                            ready.unregister(key.fileobj)
                        else:
                            target.extend(chunk)
                            require(len(target) <= LIMIT)
    finally:
        stop_group(child)
    if child.returncode != expected:
        raise CommandFailure(expected, child.returncode)
    require(True)
    return bytes(buffers["stdout"]), bytes(buffers["stderr"])


def unpack(archive, destination):
    require(archive.stat().st_size == 146864314)
    with archive.open("rb") as stream:
        require(hashlib.file_digest(stream, "sha256").hexdigest() == DIGEST)
    with tarfile.open(archive, "r:gz") as bundle:
        members = bundle.getmembers()
        require(len(members) < 50000)
        require(sum(item.size for item in members) <= 1024 * 1024 * 1024)
        # Reject links altogether: no link resolution can escape extraction.
        require(all((item.isfile() or item.isdir()) and not item.issym()
                    and not item.islnk() and item.size >= 0
                    and (item.name == "keycloak-26.0.8"
                         or item.name.startswith("keycloak-26.0.8/"))
                    and not Path(item.name).is_absolute()
                    and ".." not in Path(item.name).parts for item in members))
        bundle.extractall(destination, members=members, filter="data")
    return destination / "keycloak-26.0.8"


class Server:
    def __init__(self, base):
        self.base = base
        self.auth = None
        # Avoid proxies even if the runner environment defines one.
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def request(self, method, path, document=None, form=None):
        data = None
        headers = {}
        if self.auth:
            headers["Authorization"] = "Bearer " + self.auth
        if document is not None:
            data = json.dumps(document).encode()
            headers["Content-Type"] = "application/json"
        if form is not None:
            data = urllib.parse.urlencode(form).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        req = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        with self.opener.open(req, timeout=15) as response:
            body = response.read(LIMIT + 1)
            require(len(body) <= LIMIT)
            return body

    def json(self, method, path, document=None):
        body = self.request(method, path, document)
        return json.loads(body) if body else None


def policy(work, kind, context, value, codes=()):
    ctx, inp = work / "context.json", work / "input.json"
    ctx.write_text(json.dumps(context))
    inp.write_text(json.dumps(value))
    stdout, stderr = run([str(ROOT / "bin/policy-eval.sh"), kind, str(ctx), str(inp)],
                         timeout=20, expected=1 if codes else 0)
    require(not stderr)
    if codes:
        require(all(("FAIL " + code + ":").encode() in stdout for code in codes))
    else:
        require(not stdout)


def project(document, canaries):
    stdout, stderr = run([sys.executable, "-I", "-S", "-B",
                          str(ROOT / "bin/project-kcadm-snapshot.py"), str(ROOT),
                          str(ROOT / "realm/expected-clients.json"),
                          str(ROOT / "realm/dotmac-realm.json")],
                         data=json.dumps(document).encode())
    require(not stderr and all(value.encode() not in stdout for value in canaries))
    return json.loads(stdout)


def qualify(kc, work):
    global STAGE
    STAGE = "synthetic RSA canary generation"
    # Keycloak 26.0.8 BCPemUtilsProvider decodes headerless Base64 DER through
    # DerUtils' RSA PKCS8EncodedKeySpec. Convert explicitly to unencrypted
    # PKCS#8, entirely through bounded in-memory subprocess pipes.
    pem, _stderr = run(["openssl", "genpkey", "-algorithm", "RSA",
                        "-pkeyopt", "rsa_keygen_bits:2048"], timeout=30)
    der, _stderr = run(["openssl", "pkcs8", "-topk8", "-nocrypt", "-outform", "DER"],
                       data=pem, timeout=15)
    require(1000 <= len(der) <= 4096)
    STAGE = "native startup"
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    admin = secrets.token_urlsafe(32)
    canaries = [secrets.token_urlsafe(40) for _ in range(4)]
    canaries[2] = base64.b64encode(der).decode("ascii")
    env = {key: value for key, value in os.environ.items()
           if key in {"PATH", "JAVA_HOME", "HOME", "LANG", "TMPDIR"}}
    env.update({"KC_BOOTSTRAP_ADMIN_USERNAME": "qualification-admin",
                "JAVA_OPTS_APPEND": "-Xms128m -Xmx768m"})
    env["KC_BOOTSTRAP_ADMIN_PASSWORD"] = admin
    server = Server("http://127.0.0.1:" + str(port))
    # Discard server output at the OS sink: no unbounded log file or capture.
    with open(os.devnull, "wb") as log:
        process = spawn([str(kc / "bin/kc.sh"), "start-dev", "--http-host=127.0.0.1",
                                    "--http-port=" + str(port), "--db=dev-file"],
                        env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 180
            while True:
                require(not exited(process))
                try:
                    server.request("GET", "/realms/master/.well-known/openid-configuration")
                    break
                except Exception:
                    if time.monotonic() >= deadline:
                        raise RuntimeError("startup deadline") from None
                    time.sleep(1)
            form = {"grant_type": "password", "client_id": "admin-cli",
                    "username": "qualification-admin"}
            form["pass" + "word"] = admin
            STAGE = "bootstrap authentication"
            server.auth = json.loads(server.request("POST", "/realms/master/protocol/openid-connect/token",
                                                    form=form))["access_token"]
            STAGE = "realm declaration load"
            desired = json.loads((ROOT / "realm/dotmac-realm.json").read_text())
            desired = {k: v for k, v in desired.items() if not k.startswith("_")}
            STAGE = "realm creation"
            server.json("POST", "/admin/realms", desired)
            realm = urllib.parse.quote(desired["realm"], safe="")
            endpoint = "/admin/realms/" + realm
            STAGE = "manifest declaration load"
            manifest = json.loads((ROOT / "realm/expected-clients.json").read_text())
            governed = [entry for entry in manifest["clients"] if entry["class"] != "keycloak-builtin"]
            require(0 < len(governed) <= 32)
            for index, entry in enumerate(governed, 1):
                STAGE = "client declaration load index=" + str(index)
                client = json.loads((ROOT / entry["desired_state_file"]).read_text())
                if client["publicClient"] is False:
                    client["secret"] = canaries[0]
                    client["attributes"]["client.secret.rotated"] = canaries[1]
                client["attributes"]["saml.signing.private.key"] = canaries[2]
                client["attributes"]["qualification.unknown"] = canaries[3]
                STAGE = "client creation index=" + str(index)
                server.json("POST", endpoint + "/clients", client)
            STAGE = "bearer control creation"
            # A real bearer-only DTO exercises the other ordinary DTO branch.
            server.json("POST", endpoint + "/clients", {
                "clientId": "synthetic-bearer", "protocol": "openid-connect",
                "publicClient": False, "bearerOnly": True})
            STAGE = "raw HTTP masking controls"
            ordinary = server.request("GET", endpoint + "/clients")
            unsafe = json.loads(ordinary)
            require(all(value.encode() in ordinary for value in canaries))
            for client in unsafe:
                if client["clientId"] in {entry["clientId"] for entry in governed}:
                    # DTO type predicate, not a claim about stored secret absence.
                    if client.get("publicClient") is True or client.get("bearerOnly") is True:
                        require(client.get("secret") is None)
                if client["clientId"] == "synthetic-bearer":
                    require(client["bearerOnly"] is True and client.get("secret") is None)
                    server.json("DELETE", endpoint + "/clients/" + client["id"])
                if client["clientId"] == governed[1]["clientId"]:
                    require(client["secret"] == canaries[0])
                    require(client["attributes"]["client.secret.rotated"] == canaries[1])
            raw = server.request("POST", endpoint + "/partial-export?exportClients=true&exportGroupsAndRoles=false")
            require(all(value.encode() not in raw for value in canaries[:2]))
            require(canaries[2].encode() in raw)
            exported = json.loads(raw)
            require(isinstance(exported["clients"], list))
            # Projection uses the same public/bearer DTO predicate. This says
            # nothing about an underlying stored credential in either case.
            bearer_export = copy.deepcopy(exported)
            bearer_client = next(c for c in bearer_export["clients"]
                                 if c["clientId"] == governed[0]["clientId"])
            bearer_client["publicClient"] = False
            bearer_client["bearerOnly"] = True
            bearer_projected = project(bearer_export, canaries)
            require(next(c for c in bearer_projected["clients"]
                         if c["clientId"] == governed[0]["clientId"])["secret"] is None)
            STAGE = "real kcadm shared helper"
            config = work / "synthetic-kcadm.config"
            cli_env = dict(env)
            cli_env["KC_CLI_PASSWORD"] = admin
            # BaseConfigCredentialsCmd in 26.0.8 reads this environment name
            # when --user is supplied and the password option is absent.
            run([str(kc / "bin/kcadm.sh"), "config", "credentials", "--config", str(config),
                 "--server", server.base, "--realm", "master", "--user", "qualification-admin"],
                env=cli_env)
            projected_file = work / "projected.json"
            helper_env = dict(env, REPO_ROOT=str(ROOT), MANIFEST=str(ROOT / "realm/expected-clients.json"),
                              KC_REALM=desired["realm"], NATIVE_KCADM=str(kc / "bin/kcadm.sh"),
                              NATIVE_CONFIG=str(config), PROJECTED_FILE=str(projected_file))
            script = '''set -euo pipefail
kcadm() { "$NATIVE_KCADM" "$@" --config "$NATIVE_CONFIG"; }
source "$REPO_ROOT/bin/kcadm-snapshot.sh"
kcadm_snapshot "$PROJECTED_FILE"
cat "$PROJECTED_FILE"
'''
            stdout, stderr = run(["bash", "-c", script], env=helper_env)
            persisted = projected_file.read_bytes()
            require(stdout == persisted and not stderr)
            require(all(value.encode() not in persisted for value in canaries))
            require(b"saml.signing.private.key" not in persisted)
            projected = json.loads(persisted)
            require(projected["schemaVersion"] == 1 and projected["realm"] == desired)
            by_id = {client["clientId"]: client for client in projected["clients"]}
            raw_by_id = {client["clientId"]: client for client in exported["clients"]}
            for entry in governed:
                client = by_id[entry["clientId"]]
                require(isinstance(client["attributes"], dict))
                require(client["attributes"]["pkce.code.challenge.method"] == "S256")
                require(raw_by_id[entry["clientId"]]["attributes"]["pkce.code.challenge.method"] == "S256")
                declared_attrs = json.loads((ROOT / entry["desired_state_file"]).read_text())["attributes"]
                require(all(client["attributes"].get(key) == value
                            for key, value in declared_attrs.items()))
                require("qualification.unknown" not in client["attributes"])
                require("qualification.unknown" in projected["attributeNames"][client["id"]])
                require(client["secret"] == (None if client["publicClient"] is True
                                             or client["bearerOnly"] is True else "NONSECRET_PRESENT"))
                kind = "mobile" if entry["class"] == "mobile-native" else "web"
                policy(work, kind, entry, client)
                for mode in ("missing", "plain"):
                    bad_export = copy.deepcopy(exported)
                    bad = next(c for c in bad_export["clients"] if c["clientId"] == entry["clientId"])
                    if mode == "missing":
                        del bad["attributes"]["pkce.code.challenge.method"]
                    else:
                        bad["attributes"]["pkce.code.challenge.method"] = "plain"
                    bad_projected = project(bad_export, canaries)
                    bad = next(c for c in bad_projected["clients"] if c["clientId"] == entry["clientId"])
                    policy(work, kind, entry, bad, ("pkce",))
                bad_export = copy.deepcopy(exported)
                bad = next(c for c in bad_export["clients"] if c["clientId"] == entry["clientId"])
                del bad["implicitFlowEnabled"]
                bad_projected = project(bad_export, canaries)
                bad = next(c for c in bad_projected["clients"] if c["clientId"] == entry["clientId"])
                policy(work, kind, entry, bad, ("flow-implicit",))
            policy(work, "realm", manifest, projected["clients"])
            bad_export = copy.deepcopy(exported)
            bad_export["clients"] = [c for c in bad_export["clients"]
                                     if c["clientId"] != governed[0]["clientId"]]
            bad_export["clients"].append({"id": "synthetic-unknown", "clientId": "synthetic-unknown"})
            policy(work, "realm", manifest, project(bad_export, canaries)["clients"],
                   ("inventory-missing", "inventory-unknown"))
            STAGE = "governed policy fixtures"
            run([str(ROOT / "tests/run-policy-tests.sh")], env=env)
        finally:
            stop_group(process)


def main():
    global STAGE
    require(os.environ.get("GITHUB_ACTIONS") == "true")
    require(len(sys.argv) == 2)
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="native-masking-") as directory:
        work = Path(directory)
        STAGE = "pinned archive extraction"
        kc = unpack(Path(sys.argv[1]), work)
        qualify(kc, work)
    print("native masked export qualification passed; checks=" + str(CHECKS))


if __name__ == "__main__":
    for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGALRM):
        signal.signal(number, cancellation)
    signal.alarm(780)
    try:
        try:
            main()
        finally:
            cleanup()
    except BaseException as error:
        # Never interpolate exception text: it may contain a response/command.
        print("native masked export qualification failed; stage=" + STAGE
              + "; completed_checks=" + str(CHECKS) + safe_failure(error), file=sys.stderr)
        sys.exit(1)
