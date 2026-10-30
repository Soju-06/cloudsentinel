"""Generate a self-signed certificate for local and LAN HTTPS.

The API can serve TLS natively, but phones and browsers reject certificates
they do not trust. This script creates a small development certificate authority
that is also the server certificate, includes the right subject alternative
names (``localhost``, loopback and your LAN address), and prints how to trust it
on Windows and Android.

Run once::

    python scripts/make_dev_cert.py

Then::

    python -m cloudsentinel serve --host 0.0.0.0 --token SECRET \
        --tls-cert certs/cloudsentinel-dev.pem \
        --tls-key certs/cloudsentinel-dev-key.pem

Nothing here needs administrator rights: the Windows instructions add the
certificate to the *current user* store.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import socket
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
except ImportError:  # pragma: no cover - exercised only on missing deps
    x509 = None  # type: ignore[assignment]


DEFAULT_CERT = "cloudsentinel-dev.pem"
DEFAULT_KEY = "cloudsentinel-dev-key.pem"


def detect_lan_ip() -> str | None:
    """Best-effort local network address (no packets are actually sent)."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        try:
            probe.connect(("8.8.8.8", 80))
            return probe.getsockname()[0]
        except OSError:
            pass

    try:
        address = socket.gethostbyname(socket.gethostname())
    except OSError:
        return None
    return None if address.startswith("127.") else address


def _san_entries(ips: list[str], dns: list[str]) -> list[x509.GeneralName]:
    entries: list[x509.GeneralName] = []
    seen: set[str] = set()

    for name in ["localhost", socket.gethostname(), *dns]:
        cleaned = name.strip()
        if cleaned and cleaned.lower() not in seen:
            seen.add(cleaned.lower())
            entries.append(x509.DNSName(cleaned))

    for address in ["127.0.0.1", "::1", *ips]:
        cleaned = address.strip()
        if not cleaned:
            continue
        parsed = ipaddress.ip_address(cleaned)
        if parsed.compressed not in seen:
            seen.add(parsed.compressed)
            entries.append(x509.IPAddress(parsed))

    return entries


def build_certificate(
    *,
    ips: list[str] | None = None,
    dns: list[str] | None = None,
    days: int = 825,
    common_name: str = "CloudSentinel Dev CA",
):
    """Return ``(cert_pem, key_pem)`` as bytes."""
    if x509 is None:
        raise RuntimeError(
            "The cryptography package is required: "
            "python -m pip install -r requirements.txt"
        )

    if not 1 <= days <= 3650:
        raise ValueError("--days must be between 1 and 3650")

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CloudSentinel Lab"),
        ]
    )
    now = datetime.now(timezone.utc)

    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName(_san_entries(ips or [], dns or [])),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    cert_pem = certificate.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem


def write_certificate(
    out_dir: Path,
    *,
    ips: list[str] | None = None,
    dns: list[str] | None = None,
    days: int = 825,
    force: bool = False,
    common_name: str = "CloudSentinel Dev CA",
) -> tuple[Path, Path]:
    """Write certificate and key files, refusing to clobber unless forced."""
    cert_path = out_dir / DEFAULT_CERT
    key_path = out_dir / DEFAULT_KEY

    if not force and (cert_path.exists() or key_path.exists()):
        raise FileExistsError(
            f"{cert_path.name} or {key_path.name} already exists; "
            "use --force to replace it"
        )

    cert_pem, key_pem = build_certificate(
        ips=ips, dns=dns, days=days, common_name=common_name
    )

    out_dir.mkdir(parents=True, exist_ok=True)
    key_path.write_bytes(key_pem)
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass  # Windows: protected by the profile directory instead.
    cert_path.write_bytes(cert_pem)
    return cert_path, key_path


def _print_next_steps(cert_path: Path, key_path: Path, port: int = 8080) -> None:
    print()
    print("Certificate ready:")
    print(f"  certificate : {cert_path}")
    print(f"  private key : {key_path}  (keep this file private)")
    print()
    print("Start the API with TLS:")
    print(
        "  python -m cloudsentinel serve --host 0.0.0.0 "
        f"--port {port} --token YOUR_TOKEN \\\n"
        f"      --tls-cert {cert_path} --tls-key {key_path}"
    )
    print()
    print("Trust it on Windows (current user, no admin rights):")
    print(f"  certutil -user -addstore Root {cert_path}")
    print()
    print("Trust it on Android (phone must be unlocked):")
    print("  1. Copy the certificate file to the phone (USB or a file share).")
    print("  2. Settings -> Security -> Encryption & credentials ->")
    print("     Install a certificate -> CA certificate -> pick the file.")
    print("  3. The browser and the app trust it from then on.")
    print()
    print("WebView2 (the Windows app) uses the Windows store, so step 1 covers it.")
    print("Remove trust later with: certutil -user -delstore Root <subject>")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Create a self-signed certificate for CloudSentinel HTTPS"
    )
    parser.add_argument(
        "--out",
        default="certs",
        help="output directory (default: certs)",
    )
    parser.add_argument(
        "--ip",
        action="append",
        default=[],
        help="extra IP address to include (repeatable)",
    )
    parser.add_argument(
        "--dns",
        action="append",
        default=[],
        help="extra DNS name to include (repeatable)",
    )
    parser.add_argument(
        "--days",
        type=int,
        default=825,
        help="validity in days (default 825)",
    )
    parser.add_argument(
        "--common-name",
        default="CloudSentinel Dev CA",
        help="certificate common name",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="overwrite existing certificate files",
    )
    args = parser.parse_args(argv)

    addresses = list(args.ip)
    lan_ip = detect_lan_ip()
    if lan_ip and lan_ip not in addresses:
        addresses.append(lan_ip)
        print(f"Detected LAN address: {lan_ip}")

    try:
        cert_path, key_path = write_certificate(
            Path(args.out),
            ips=addresses,
            dns=args.dns,
            days=args.days,
            force=args.force,
            common_name=args.common_name,
        )
    except (FileExistsError, RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    _print_next_steps(cert_path, key_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
