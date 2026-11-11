"""Bounded scanner adapters: Nessus, Greenbone/OpenVAS, and Nmap."""

import base64
import csv
import hashlib
import io
import ipaddress
import json
import re
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from typing import Literal
from uuid import NAMESPACE_URL, UUID, uuid5

from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

from threatpulse.models import CveId

Scanner = Literal["nessus", "openvas", "nmap"]
Format = Literal["xml", "csv"]
FORMATS = {"nessus": ("xml", "csv"), "openvas": ("xml", "csv"), "nmap": ("xml",)}
MAX_BYTES = 25 * 1024 * 1024
MAX_RECORDS = 100000
MAX_XML_NODES = 500000
csv.field_size_limit(MAX_BYTES)
CVE = re.compile(r"\bCVE-\d{4}-\d{4,}(?![\w-])", re.I)
SEVERITIES = ("UNKNOWN", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")


class ScanImportError(ValueError):
    """A safe structural error without raw scanner output or credentials."""


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def sha(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Service(Strict):
    port: int = Field(ge=0, le=65535)
    protocol: str
    state: str = "reported"
    name: str = ""
    product: str = ""
    version: str = ""
    cpes: list[str] = Field(default_factory=list)
    detection_confidence: str | None = None


class Asset(Strict):
    asset_key: str
    address: str
    hostnames: list[str] = Field(default_factory=list)
    scanned_at: AwareDatetime | None = None
    reported_time: str = ""
    credentialed: bool | None = None
    services: list[Service] = Field(default_factory=list)


class Finding(Strict):
    finding_id: str
    asset_key: str
    source_locator: str
    rule_id: str
    title: str
    port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str | None = None
    severity: Literal["UNKNOWN", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"] = (
        "UNKNOWN"
    )
    status: Literal["reported", "candidate", "informational", "negative"] = "reported"
    cves: list[CveId] = Field(default_factory=list, max_length=5000)
    description: str = ""
    solution: str = ""
    evidence: str = ""
    scanner_score: Decimal | None = Field(
        default=None, ge=0, le=10, allow_inf_nan=False
    )
    scanner_score_version: str | None = None
    scanner_vector: str = ""
    qod_percent: Decimal | None = Field(default=None, ge=0, le=100, allow_inf_nan=False)
    flags: list[str] = Field(default_factory=list)


class ScanReport(Strict):
    dataset_kind: Literal["scanner_import"] = "scanner_import"
    schema_version: Literal[1] = 1
    scan_id: UUID
    scanner: Scanner
    format: Format
    filename: str
    imported_at: AwareDatetime
    scanned_at: AwareDatetime | None = None
    time_override: AwareDatetime | None = None
    synthetic: bool = False
    raw_sha256: str
    raw_base64: str
    assets: list[Asset]
    findings: list[Finding]
    warnings: list[str] = Field(default_factory=list)
    coverage: dict = Field(default_factory=dict)

    @model_validator(mode="after")
    def integrity(self):
        raw = base64.b64decode(self.raw_base64, validate=True)
        if len(raw) > MAX_BYTES or hashlib.sha256(raw).hexdigest() != self.raw_sha256:
            raise ValueError("Original scan checksum or size mismatch")
        expected = import_id(
            self.raw_sha256,
            self.scanner,
            self.format,
            self.time_override,
            self.synthetic,
        )
        if self.scan_id != expected or self.format not in FORMATS[self.scanner]:
            raise ValueError("Scan identity/format mismatch")
        keys = {a.asset_key for a in self.assets}
        if any(asset_identity(a.address)[0] != a.asset_key for a in self.assets):
            raise ValueError("Asset identity does not match its reported address")
        if len(keys) != len(self.assets) or len(
            {f.finding_id for f in self.findings}
        ) != len(self.findings):
            raise ValueError("Duplicate normalized identity")
        if len(self.findings) > MAX_RECORDS or len(self.assets) > MAX_RECORDS:
            raise ValueError("Scan exceeds record limit")
        if (
            sum(len(f.cves) or 1 for f in self.findings) > MAX_RECORDS
            or sum(len(a.services) for a in self.assets) > MAX_RECORDS
        ):
            raise ValueError("Scan exceeds relationship/service limits")
        for finding in self.findings:
            if finding.asset_key not in keys or finding.finding_id != finding_id(
                finding
            ):
                raise ValueError("Finding identity/provenance mismatch")
        return self


def import_id(raw_sha, scanner, format, override, synthetic=False):
    stamp = override.astimezone(UTC).isoformat() if override else None
    return uuid5(
        NAMESPACE_URL,
        canonical(["threatpulse_scan_v1", raw_sha, scanner, format, stamp, synthetic]),
    )


def finding_id(finding):
    return sha(finding.model_dump(mode="json", exclude={"finding_id"}))


def parsed_time(value):
    value = (value or "").strip()
    try:
        if re.fullmatch(r"\d{9,12}(?:\.\d+)?", value):
            return datetime.fromtimestamp(float(value), UTC)
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return result.astimezone(UTC) if result.utcoffset() is not None else None
    except (ValueError, OverflowError, OSError):
        return None


def asset_identity(value):
    value = value.strip()
    if not value or len(value) > 512 or any(ord(c) < 32 for c in value):
        raise ScanImportError("A host address/name is missing or invalid.")
    try:
        address = str(ipaddress.ip_address(value))
        return "ip:" + address, address
    except ValueError:
        address = value.lower().rstrip(".")
        return "host:" + address, value


def number(value, upper):
    if value is None or str(value).strip() in ("", "N/A", "None", "-"):
        return None
    try:
        result = Decimal(str(value).strip())
        return result if result.is_finite() and 0 <= result <= upper else None
    except InvalidOperation:
        return None


def severity(value):
    label = str(value or "").strip().upper()
    return {
        "0": "INFO",
        "1": "LOW",
        "2": "MEDIUM",
        "3": "HIGH",
        "4": "CRITICAL",
        "NONE": "INFO",
        "LOG": "INFO",
    }.get(label, label if label in SEVERITIES else "UNKNOWN")


def cves(value):
    value = value or ""
    found = sorted({m.upper() for m in CVE.findall(value)})
    flags = (
        ["UNPARSED_CVE_REFERENCE"]
        if re.search(r"\bCVE[-_]", CVE.sub("", value), re.I)
        else []
    )
    return found, flags


def port(value):
    value = str(value or "").strip()
    if value.lower() in ("", "none", "n/a") or re.fullmatch(
        r"general(?:/[\w-]+)?", value, re.I
    ):
        return None, None
    match = re.fullmatch(r"(\d{1,5})(?:/([A-Za-z0-9_-]+))?", value)
    if not match or int(match[1]) > 65535:
        raise ScanImportError(
            "A finding has an invalid port; check the selected format."
        )
    return int(match[1]), match[2].lower() if match[2] else None


class Builder:
    def __init__(self):
        self.assets = {}
        self.findings = []
        self.warnings = set()
        self.scanned_at = None
        self.coverage = {"scope": "exported_records_only"}

    def asset(self, address, hostname="", stamp="", credentialed=None):
        key, address = asset_identity(address)
        if key not in self.assets:
            self.assets[key] = Asset(
                asset_key=key,
                address=address,
                reported_time=stamp,
                scanned_at=parsed_time(stamp),
                credentialed=credentialed,
            )
        result = self.assets[key]
        if hostname and hostname not in result.hostnames:
            result.hostnames.append(hostname)
        if len(self.assets) > MAX_RECORDS:
            raise ScanImportError("Too many assets in this scan.")
        return result

    def finding(self, asset, locator, **values):
        flags = list(values.pop("flags", []))
        if values.get("protocol"):
            values["protocol"] = values["protocol"].strip().lower()
        for field in ("title", "description", "solution", "evidence"):
            value = values.get(field, "") or ""
            if len(value) > 20000:
                flags.append("EVIDENCE_PREVIEW_TRUNCATED")
                value = value[:20000]
            values[field] = value
        item = Finding(
            finding_id="pending",
            asset_key=asset.asset_key,
            source_locator=locator,
            flags=sorted(set(flags)),
            **values,
        )
        item.finding_id = finding_id(item)
        self.findings.append(item)
        if item.port is not None:
            service = Service(port=item.port, protocol=item.protocol or "unknown")
            if not any(
                s.port == service.port and s.protocol == service.protocol
                for s in asset.services
            ):
                asset.services.append(service)
        if len(self.findings) > MAX_RECORDS:
            raise ScanImportError("Too many findings in this scan.")


def text(node, path):
    return (node.findtext(path) or "").strip()


def nessus_xml(root, builder):
    if root.tag != "NessusClientData_v2" or root.find("Report") is None:
        raise ScanImportError("Expected a Nessus .nessus XML report.")
    for hi, host in enumerate(root.findall(".//Report/ReportHost")):
        props = {
            n.get("name"): n.text or "" for n in host.findall("HostProperties/tag")
        }
        stamp = props.get("HOST_END_TIMESTAMP") or props.get("HOST_END", "")
        credentialed = {"true": True, "yes": True, "false": False, "no": False}.get(
            props.get("Credentialed_Scan", "").lower()
        )
        asset = builder.asset(
            props.get("host-ip") or host.get("name", ""),
            props.get("host-fqdn", ""),
            stamp,
            credentialed,
        )
        for fi, node in enumerate(host.findall("ReportItem")):
            found, flags = cves(" ".join(n.text or "" for n in node.findall("cve")))
            risk = severity(node.get("severity") or text(node, "risk_factor"))
            p, proto = port(node.get("port"))
            if p == 0:
                p = None
            vector = (
                text(node, "cvss4_vector")
                or text(node, "cvss3_vector")
                or text(node, "cvss_vector")
            )
            score = (
                text(node, "cvss4_base_score")
                or text(node, "cvss3_base_score")
                or text(node, "cvss_base_score")
            )
            version = (
                "4.0"
                if text(node, "cvss4_base_score")
                else "3.x"
                if text(node, "cvss3_base_score")
                else "2.0"
                if score
                else None
            )
            if vector.startswith(("CVSS:3.0/", "CVSS:3.1/")):
                version = vector.split("/")[0].split(":")[1]
            builder.finding(
                asset,
                f"host[{hi}]/ReportItem[{fi}]",
                rule_id=node.get("pluginID", ""),
                title=node.get("pluginName", "Nessus finding"),
                port=p,
                protocol=node.get("protocol") or proto,
                severity=risk,
                status="informational" if risk == "INFO" else "reported",
                cves=found,
                description=text(node, "description") or text(node, "synopsis"),
                solution=text(node, "solution"),
                evidence=text(node, "plugin_output"),
                scanner_score=number(score, 10),
                scanner_score_version=version,
                scanner_vector=vector,
                flags=flags,
            )


def openvas_xml(root, builder):
    if root.tag not in ("report", "get_reports_response"):
        raise ScanImportError("Expected an OpenVAS/Greenbone XML report.")
    if root.tag == "get_reports_response" and not root.get("status", "200").startswith(
        "2"
    ):
        raise ScanImportError("This is a GMP error response, not an exported report.")
    containers = root.findall(".//results")
    if not containers:
        raise ScanImportError("OpenVAS XML must contain a results element.")
    stamp = next((n.text for n in root.iter("scan_end") if n.text), "")
    builder.scanned_at = parsed_time(stamp)
    full = next(
        (text(n, "full") for n in root.iter("result_count") if text(n, "full")), ""
    )
    if full.isdigit():
        builder.coverage["reported_full_results"] = int(full)
    count = 0
    for container in containers:
        for node in container.findall("result"):
            count += 1
            host = node.find("host")
            address = (host.text or "").strip() if host is not None else ""
            asset = builder.asset(address, text(node, "host/hostname"), stamp)
            nvt = node.find("nvt")
            if nvt is None:
                raise ScanImportError("OpenVAS result is missing its NVT element.")
            values = [text(nvt, "cve"), text(node, "cve")]
            values.extend(
                r.get("id", "")
                for r in nvt.findall("refs/ref")
                if r.get("type", "").lower() == "cve"
            )
            found, flags = cves(" ".join(values))
            tags = dict(
                part.split("=", 1)
                for part in text(nvt, "tags").split("|")
                if "=" in part
            )
            threat = text(node, "threat")
            negative = threat.lower() == "false positive" or text(node, "severity") in (
                "-1",
                "-1.0",
            )
            risk = severity(threat)
            p, proto = port(text(node, "port"))
            solution = text(node, "solution") or tags.get("solution", "")
            builder.finding(
                asset,
                f"result[{count}]:{node.get('id', '')}",
                rule_id=nvt.get("oid", ""),
                title=text(node, "name") or text(nvt, "name") or "OpenVAS finding",
                port=p,
                protocol=proto,
                severity=risk,
                status="negative"
                if negative
                else "informational"
                if risk == "INFO"
                else "reported",
                cves=found,
                description=text(node, "description") or tags.get("summary", ""),
                solution=solution,
                evidence=text(node, "description"),
                scanner_score=number(
                    text(node, "severity") or text(nvt, "cvss_base"), 10
                ),
                scanner_vector=tags.get("cvss_base_vector", ""),
                qod_percent=number(text(node, "qod/value"), 100),
                flags=flags,
            )
    if full.isdigit() and count < int(full):
        builder.warnings.add("FILTERED_OR_PARTIAL_EXPORT")


def nmap_xml(root, builder):
    if root.tag != "nmaprun" or root.get("scanner", "nmap") != "nmap":
        raise ScanImportError("Expected Nmap XML generated with -oX.")
    builder.scanned_at = (
        parsed_time(root.find("runstats/finished").get("time"))
        if root.find("runstats/finished") is not None
        else None
    )
    for hi, node in enumerate(root.findall("host")):
        addresses = [
            n.get("addr", "")
            for n in node.findall("address")
            if n.get("addrtype") in ("ipv4", "ipv6")
        ]
        names = [n.get("name", "") for n in node.findall("hostnames/hostname")]
        asset = builder.asset(
            next(iter(addresses or names), ""),
            next(iter(names), ""),
            node.get("endtime", ""),
        )
        asset.hostnames = sorted(set(asset.hostnames + names))
        for pi, element in enumerate(node.findall("ports/port")):
            p, _ = port(element.get("portid"))
            if p is None:
                raise ScanImportError("Nmap port is missing its port number.")
            service = element.find("service")
            state = element.find("state")
            item = Service(
                port=p,
                protocol=element.get("protocol", "unknown").lower(),
                state=state.get("state", "unknown") if state is not None else "unknown",
                name=service.get("name", "") if service is not None else "",
                product=service.get("product", "") if service is not None else "",
                version=service.get("version", "") if service is not None else "",
                cpes=[n.text for n in service.findall("cpe") if n.text]
                if service is not None
                else [],
                detection_confidence=service.get("conf")
                if service is not None
                else None,
            )
            asset.services.append(item)
            if item.state in ("open", "open|filtered"):
                builder.finding(
                    asset,
                    f"host[{hi}]/port[{pi}]/inventory",
                    rule_id="service-inventory",
                    title=" ".join(
                        v for v in (item.name, item.product, item.version) if v
                    )
                    or "Open service",
                    port=p,
                    protocol=item.protocol,
                    severity="INFO",
                    status="informational",
                    description=(
                        "Service fingerprint; CVE applicability has not "
                        "been established."
                    ),
                    flags=["SERVICE_FINGERPRINT_ONLY"]
                    + (
                        ["PORT_STATE_UNCERTAIN"]
                        if item.state == "open|filtered"
                        else []
                    ),
                )
                for si, script in enumerate(element.findall("script")):
                    nmap_script(
                        builder,
                        asset,
                        script,
                        f"host[{hi}]/port[{pi}]/script[{si}]",
                        p,
                        item.protocol,
                    )
        for si, script in enumerate(node.findall("hostscript/script")):
            nmap_script(
                builder, asset, script, f"host[{hi}]/hostscript[{si}]", None, None
            )


def nmap_script(builder, asset, script, locator, p, protocol, rule_id=None):
    rule_id = rule_id or script.get("id", "nse-script")
    groups = [
        node
        for node in script.findall("table")
        if node.find("elem[@key='state']") is not None
    ]
    if groups:
        for index, node in enumerate(groups):
            nmap_script(
                builder, asset, node, locator + f"/table[{index}]", p, protocol, rule_id
            )
        return
    evidence = (
        script.get("output", "")
        + "\n"
        + "\n".join((n.get("key", "") + " " + (n.text or "")) for n in script.iter())
    )
    found, flags = cves(evidence)
    if not found:
        return
    states = " ".join(
        n.text or "" for n in script.iter("elem") if n.get("key", "").lower() == "state"
    )
    negative = bool(
        re.search(
            r"\b(?:NOT VULNERABLE|NOT AFFECTED|FALSE POSITIVE)\b",
            states or evidence,
            re.I,
        )
    )
    remaining = re.sub(
        r"\b(?:NOT VULNERABLE|NOT AFFECTED|FALSE POSITIVE)\b",
        "",
        states or evidence,
        flags=re.I,
    )
    if negative and re.search(r"\bVULNERABLE\b", remaining, re.I):
        flags.append("CONFLICTING_NSE_STATUS")
        negative = False
    builder.finding(
        asset,
        locator,
        rule_id=rule_id,
        title=rule_id,
        port=p,
        protocol=protocol,
        status="negative" if negative else "candidate",
        cves=found,
        description="CVE reference reported by an NSE script; verify applicability.",
        evidence=evidence,
        flags=flags + ["SCRIPT_REFERENCE_REQUIRES_VERIFICATION"],
    )


def header(value):
    return re.sub(r"[^a-z0-9]", "", value.lower().lstrip("\ufeff"))


def csv_report(raw, scanner, builder):
    try:
        content = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ScanImportError(
            "CSV must be UTF-8; re-export or convert its encoding."
        ) from exc
    reader = csv.DictReader(io.StringIO(content, newline=""), strict=True)
    names = reader.fieldnames or []
    normalized = [header(name) for name in names]
    if len(set(normalized)) != len(normalized):
        raise ScanImportError("CSV has duplicate column names.")
    required = "pluginid" if scanner == "nessus" else "nvtoid"
    if required not in normalized or not {"host", "ip"} & set(normalized):
        raise ScanImportError(
            "CSV headers do not match the selected scanner; include "
            "Host/IP and Plugin ID/NVT OID."
        )
    if not {"cve", "cves"} & set(normalized):
        builder.warnings.add("CVE_COLUMN_NOT_EXPORTED")
    for ri, original in enumerate(reader, 2):
        if None in original or any(value is None for value in original.values()):
            raise ScanImportError(f"CSV row {ri} has the wrong number of columns.")
        row = {header(key): value for key, value in original.items()}
        if not any(value.strip() for value in row.values()):
            continue

        def get(*keys, row=row):
            return next((row[k].strip() for k in keys if row.get(k, "").strip()), "")

        asset = builder.asset(
            get("ip", "host"), get("hostname"), get("scanend", "scannedat", "timestamp")
        )
        found, flags = cves(get("cve", "cves"))
        risk = severity(get("risk", "riskfactor", "threat"))
        if risk == "UNKNOWN" and get("severity").upper() in SEVERITIES:
            risk = get("severity").upper()
        explicitly_informational = risk == "INFO"
        score_version = next(
            (
                (key, version)
                for key, version in (
                    ("cvssv40basescore", "4.0"),
                    ("cvssv31basescore", "3.1"),
                    ("cvssv30basescore", "3.0"),
                    ("cvssv20basescore", "2.0"),
                    ("cvssv2basescore", "2.0"),
                )
                if get(key)
            ),
            (None, None),
        )
        score_value = (
            get(score_version[0])
            if score_version[0]
            else get("cvssbasescore", "cvss", "severity")
        )
        score = number(score_value, 10)
        if risk == "UNKNOWN" and score is not None:
            risk = (
                "CRITICAL"
                if score >= 9
                else "HIGH"
                if score >= 7
                else "MEDIUM"
                if score >= 4
                else "LOW"
                if score > 0
                else "INFO"
            )
        p, proto = port(get("port"))
        if scanner == "nessus" and p == 0:
            p = None
        negative = get("threat", "risk").lower() == "false positive" or score_value in (
            "-1",
            "-1.0",
        )
        builder.finding(
            asset,
            f"csv:row:{ri}",
            rule_id=get(required),
            title=get("name", "nvtname") or "Scanner finding",
            port=p,
            protocol=get("protocol", "portprotocol") or proto,
            severity=risk,
            status="negative"
            if negative
            else "informational"
            if explicitly_informational
            else "reported",
            cves=found,
            description=get("description", "summary", "synopsis"),
            solution=get("solution", "solutiondescription"),
            evidence=get(
                "pluginoutput", "vulnerabilitydetectionresult", "description", "summary"
            ),
            scanner_score=score,
            scanner_score_version=score_version[1],
            qod_percent=number(get("qod", "qodvalue"), 100),
            flags=flags,
        )


ADAPTERS = {
    ("nessus", "xml"): nessus_xml,
    ("openvas", "xml"): openvas_xml,
    ("nmap", "xml"): nmap_xml,
}


def parse_scan(
    raw: bytes,
    scanner: Scanner,
    format: Format,
    *,
    filename="scan",
    scanned_at=None,
    synthetic=False,
    imported_at=None,
):
    if scanner not in FORMATS or format not in FORMATS[scanner]:
        raise ScanImportError("Unsupported scanner/format combination.")
    if not raw or len(raw) > MAX_BYTES:
        raise ScanImportError("Scan must be nonempty and no larger than 25 MiB.")
    if scanned_at and scanned_at.utcoffset() is None:
        raise ScanImportError("Scan time requires an explicit timezone.")
    builder = Builder()
    try:
        if format == "xml":
            # Nmap's harmless <!DOCTYPE nmaprun> is allowed; entities/external
            # references are blocked. XInclude and XSLT are never processed.
            events = SafeET.iterparse(
                io.BytesIO(raw),
                events=("start", "end"),
                forbid_entities=True,
                forbid_external=True,
            )
            count = depth = 0
            for event, _node in events:
                if event == "start":
                    count += 1
                    depth += 1
                    if count > MAX_XML_NODES or depth > 128:
                        raise ScanImportError(
                            "XML exceeds the structural import limits."
                        )
                else:
                    depth -= 1
            root = events.root
            for node in root.iter():
                node.tag = node.tag.rsplit("}", 1)[-1]
            ADAPTERS[(scanner, format)](root, builder)
        else:
            csv_report(raw, scanner, builder)
    except ScanImportError:
        raise
    except (
        ValueError,
        TypeError,
        DefusedXmlException,
        SafeET.ParseError,
        csv.Error,
    ) as exc:
        raise ScanImportError(
            "Could not parse this file; check scanner, format, encoding, "
            "and required fields."
        ) from exc
    if scanned_at:
        builder.scanned_at = scanned_at.astimezone(UTC)
        for asset in builder.assets.values():
            asset.scanned_at = builder.scanned_at
    if (
        not builder.scanned_at
        and builder.assets
        and all(a.scanned_at for a in builder.assets.values())
    ):
        builder.scanned_at = max(a.scanned_at for a in builder.assets.values())
    for asset in builder.assets.values():
        if asset.scanned_at is None and builder.scanned_at:
            asset.scanned_at = builder.scanned_at
    checksum = hashlib.sha256(raw).hexdigest()
    return ScanReport(
        scan_id=import_id(checksum, scanner, format, scanned_at, synthetic),
        scanner=scanner,
        format=format,
        filename=filename.replace("\\", "/").split("/")[-1],
        imported_at=imported_at or datetime.now(UTC),
        scanned_at=builder.scanned_at,
        time_override=scanned_at,
        synthetic=synthetic,
        raw_sha256=checksum,
        raw_base64=base64.b64encode(raw).decode(),
        assets=list(builder.assets.values()),
        findings=builder.findings,
        warnings=sorted(builder.warnings),
        coverage=builder.coverage,
    )
