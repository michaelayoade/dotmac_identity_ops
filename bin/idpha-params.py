#!/usr/bin/env python3
"""idpha-params.py - validate and consume the typed IdP HA params document.

Subcommands (all offline, standard library only):
  validate --schema S --params P
  export   --schema S --params P --op OP     shell assignments for one operation
  plan-doc --op OP --node NAME --effects F   canonical effect summary + digest

The validator implements the subset of JSON Schema that ha/params.schema.json
uses (type, enum, const, pattern, format, min/max, length, items, properties,
required, additionalProperties, $ref) and FAILS CLOSED on any keyword or format
it does not know, so a schema edit cannot silently weaken validation.
Error messages name the JSON path and the rule, never the offending value.
"""
import argparse
import hashlib
import ipaddress
import json
import re
import shlex
import sys

KNOWN = {"$schema", "$id", "$defs", "$ref", "title", "description", "type", "enum", "const",
         "pattern", "format", "minimum", "maximum", "minLength", "maxLength", "minItems",
         "maxItems", "items", "properties", "required", "additionalProperties", "uniqueItems"}


def fmt_ok(name, v):
    if name == "ipv4":
        try:
            return isinstance(ipaddress.ip_address(v), ipaddress.IPv4Address) and re.fullmatch(r"\d+(\.\d+){3}", v) is not None
        except ValueError:
            return False
    if name == "cidr4":
        try:
            n = ipaddress.ip_network(v, strict=True)
            return n.version == 4 and "/" in v
        except ValueError:
            return False
    if name == "hostname":
        return re.fullmatch(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+", v) is not None
    if name == "abs-path":
        return re.fullmatch(r"/[A-Za-z0-9._@+-]+(/[A-Za-z0-9._@+-]+)*", v) is not None
    raise ValueError("unknown format " + name)


def check(schema, inst, root, path, errs):
    for k in schema:
        if k not in KNOWN:
            errs.append(f"{path}: schema uses unsupported keyword '{k}'")
            return
    if "$ref" in schema:
        ref = schema["$ref"]
        if not ref.startswith("#/$defs/") or ref[8:] not in root.get("$defs", {}):
            errs.append(f"{path}: unresolvable $ref")
            return
        check(root["$defs"][ref[8:]], inst, root, path, errs)
        return
    t = schema.get("type")
    tmap = {"object": dict, "array": list, "string": str, "boolean": bool, "integer": int}
    if t:
        ok = isinstance(inst, tmap[t]) and not (t == "integer" and isinstance(inst, bool))
        if not ok:
            errs.append(f"{path}: must be of type {t}")
            return
    if "const" in schema and inst != schema["const"]:
        errs.append(f"{path}: must equal the required constant")
    if "enum" in schema and inst not in schema["enum"]:
        errs.append(f"{path}: not one of the allowed values")
    if isinstance(inst, str):
        if "pattern" in schema and not re.fullmatch(schema["pattern"], inst):
            errs.append(f"{path}: does not match the required pattern")
        if "format" in schema:
            try:
                if not fmt_ok(schema["format"], inst):
                    errs.append(f"{path}: not a valid {schema['format']}")
            except ValueError as e:
                errs.append(f"{path}: {e}")
        if "minLength" in schema and len(inst) < schema["minLength"]:
            errs.append(f"{path}: too short")
        if "maxLength" in schema and len(inst) > schema["maxLength"]:
            errs.append(f"{path}: too long")
    if isinstance(inst, int) and not isinstance(inst, bool):
        if "minimum" in schema and inst < schema["minimum"]:
            errs.append(f"{path}: below the minimum")
        if "maximum" in schema and inst > schema["maximum"]:
            errs.append(f"{path}: above the maximum")
    if isinstance(inst, list):
        if "minItems" in schema and len(inst) < schema["minItems"]:
            errs.append(f"{path}: too few items")
        if "maxItems" in schema and len(inst) > schema["maxItems"]:
            errs.append(f"{path}: too many items")
        if schema.get("uniqueItems") and len({json.dumps(i, sort_keys=True) for i in inst}) != len(inst):
            errs.append(f"{path}: items must be unique")
        if "items" in schema:
            for i, it in enumerate(inst):
                check(schema["items"], it, root, f"{path}[{i}]", errs)
    if isinstance(inst, dict):
        props = schema.get("properties", {})
        for r in schema.get("required", []):
            if r not in inst:
                errs.append(f"{path}.{r}: required value is missing")
        ap = schema.get("additionalProperties", True)
        for k, v in inst.items():
            if k in props:
                check(props[k], v, root, f"{path}.{k}", errs)
            elif ap is False:
                errs.append(f"{path}.{k}: unknown parameter")
            elif isinstance(ap, dict):
                check(ap, v, root, f"{path}.{k}", errs)


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def validate(schema_path, params_path):
    schema, doc = load(schema_path), load(params_path)
    errs = []
    check(schema, doc, schema, "$", errs)
    return doc, errs


ENV_NODE = {"name": "NODE_NAME", "overlay_addr": "OVERLAY_ADDR", "vip_addr": "VIP_ADDR", "ha_dir": "HA_DIR",
            "patroni_conf": "PATRONI_CONF", "wg_if": "WG_IF", "wg_port": "WG_PORT", "wg_unit": "WG_UNIT",
            "primary_nic": "PRIMARY_NIC", "ssh_port": "SSH_PORT"}


ALSO = {"host-check": [("harden-ha", ["apt_upgrade_time"]), ("ha-install", ["kc_hostname"])]}


def scalar(v):
    if isinstance(v, bool):
        return "1" if v else "0"
    if isinstance(v, list):
        return " ".join(str(x) for x in v)
    return str(v)


def export(doc, op):
    ops = doc.get("operations", {})
    if op not in ops:
        sys.stderr.write(f"REFUSING: params carry no section for operation '{op}'\n")
        sys.exit(3)
    out = {}
    node = doc["node"]
    for k, v in node.items():
        if k in ENV_NODE:
            out[ENV_NODE[k]] = scalar(v)
    for i, p in enumerate(node["peers"], 1):
        out[f"PEER_OVERLAY_{i}"] = p["overlay_addr"]
        out[f"PEER_PUBLIC_{i}"] = p["public_addr"]
    if "cert_files" in node:
        out["CERT_FILES"] = " ".join(f"{c['name']}={c['path']}" for c in node["cert_files"])
    # Read-only checks grade what other operations installed: borrow those values.
    for src, keys in ALSO.get(op, []):
        for k in keys:
            if k in ops.get(src, {}):
                out[k.upper()] = scalar(ops[src][k])
    for k, v in ops[op].items():
        out[k.upper()] = scalar(v)
    for k in sorted(out):
        print(f"{k}={shlex.quote(out[k])}")
    print("export " + " ".join(sorted(out)))


def plan_doc(op, node, effects_path):
    effects = []
    with open(effects_path, encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            parts = line.split("\t")
            kind = parts[0]
            if kind == "write":
                effects.append({"kind": "write", "path": parts[1], "mode": parts[2], "sha256": parts[3], "replaces": parts[4] == "1"})
            elif kind == "remove":
                effects.append({"kind": "remove", "path": parts[1]})
            elif kind == "restore":
                effects.append({"kind": "restore", "path": parts[1]})
            else:
                effects.append({"kind": kind, "detail": parts[1] if len(parts) > 1 else ""})
    body = {"operation": op, "node": node, "effects": effects}
    canon = json.dumps(body, sort_keys=True, separators=(",", ":"))
    body["digest"] = "sha256:" + hashlib.sha256(canon.encode()).hexdigest()
    print(json.dumps(body, sort_keys=True, indent=2))


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("validate", "export"):
        s = sub.add_parser(name)
        s.add_argument("--schema", required=True)
        s.add_argument("--params", required=True)
        if name == "export":
            s.add_argument("--op", required=True)
    s = sub.add_parser("plan-doc")
    s.add_argument("--op", required=True)
    s.add_argument("--node", required=True)
    s.add_argument("--effects", required=True)
    sub.add_parser("digest-of")
    a = ap.parse_args()
    if a.cmd == "plan-doc":
        plan_doc(a.op, a.node, a.effects)
        return
    if a.cmd == "digest-of":
        print(json.load(sys.stdin)["digest"])
        return
    try:
        doc, errs = validate(a.schema, a.params)
    except (OSError, ValueError) as e:
        sys.stderr.write(f"REFUSING: cannot read params or schema: {type(e).__name__}\n")
        sys.exit(2)
    if errs:
        sys.stderr.write("REFUSING: params do not satisfy ha/params.schema.json:\n")
        for e in errs:
            sys.stderr.write("  " + e + "\n")
        sys.exit(2)
    if a.cmd == "export":
        export(doc, a.op)


if __name__ == "__main__":
    main()
