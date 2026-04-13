from __future__ import annotations

import asyncio
import ssl
from datetime import datetime, timezone
from typing import Any

from cryptography import x509
from cryptography.hazmat.backends import default_backend


class SSLSecurityAnalyzer:
    def __init__(self, timeout: float = 8.0) -> None:
        self.timeout = timeout

    async def analyze(self, host: str, port: int = 443) -> dict[str, Any]:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    host=host,
                    port=port,
                    ssl=self._make_context(),
                    server_hostname=host,
                ),
                timeout=self.timeout,
            )
        except Exception as exc:
            return {
                "host": host,
                "port": port,
                "reachable": False,
                "error": str(exc),
                "issues": ["TLS connection could not be established."],
            }

        try:
            ssl_object = writer.get_extra_info("ssl_object")
            certificate = ssl_object.getpeercert() if ssl_object else {}
            cert_binary = ssl_object.getpeercert(binary_form=True) if ssl_object else None
            parsed_binary = self._parse_certificate_binary(cert_binary)
            cipher = ssl_object.cipher() if ssl_object else None
            negotiated_protocol = ssl_object.version() if ssl_object else None

            issuer = parsed_binary.get("issuer") or self._flatten_name(certificate.get("issuer"))
            subject = parsed_binary.get("subject") or self._flatten_name(certificate.get("subject"))
            san = parsed_binary.get("san") or [
                value for entry_type, value in certificate.get("subjectAltName", []) if entry_type == "DNS"
            ]

            not_before = parsed_binary.get("not_before") or self._parse_asn1_time(certificate.get("notBefore"))
            not_after = parsed_binary.get("not_after") or self._parse_asn1_time(certificate.get("notAfter"))
            now = datetime.now(timezone.utc)
            certificate_valid = bool(not_before and not_after and not_before <= now <= not_after)

            tls10_supported, tls11_supported = await asyncio.gather(
                self._supports_version(host, port, ssl.TLSVersion.TLSv1),
                self._supports_version(host, port, ssl.TLSVersion.TLSv1_1),
            )

            cipher_name = cipher[0] if cipher else None
            cipher_protocol = cipher[1] if cipher else None
            cipher_bits = cipher[2] if cipher else None
            weak_cipher = self._is_weak_cipher(cipher_name, cipher_bits)

            issues: list[str] = []
            if not certificate_valid:
                issues.append("Certificate is expired or not yet valid.")
            if not_after:
                days_remaining = (not_after - now).days
                if days_remaining < 30:
                    issues.append(f"Certificate expires in {days_remaining} day(s).")
            if tls10_supported:
                issues.append("Server supports TLS 1.0.")
            if tls11_supported:
                issues.append("Server supports TLS 1.1.")
            if weak_cipher:
                issues.append("Negotiated cipher appears weak.")

            return {
                "host": host,
                "port": port,
                "reachable": True,
                "certificate": {
                    "subject": subject,
                    "issuer": issuer,
                    "san": san,
                    "not_before": not_before.isoformat() if not_before else None,
                    "not_after": not_after.isoformat() if not_after else None,
                    "valid_now": certificate_valid,
                },
                "protocol": negotiated_protocol,
                "supported_protocols": {
                    "TLSv1.0": tls10_supported,
                    "TLSv1.1": tls11_supported,
                },
                "cipher": {
                    "name": cipher_name,
                    "protocol": cipher_protocol,
                    "bits": cipher_bits,
                    "weak": weak_cipher,
                },
                "issues": issues,
            }
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    def _make_context(self) -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context

    async def _supports_version(self, host: str, port: int, version: ssl.TLSVersion) -> bool:
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.minimum_version = version
            context.maximum_version = version
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host=host, port=port, ssl=context, server_hostname=host),
                timeout=self.timeout,
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True
        except Exception:
            return False

    @staticmethod
    def _flatten_name(entries) -> str:
        if not entries:
            return ""
        parts: list[str] = []
        for group in entries:
            for key, value in group:
                parts.append(f"{key}={value}")
        return ", ".join(parts)

    @staticmethod
    def _parse_asn1_time(value: str | None) -> datetime | None:
        if not value:
            return None
        for fmt in ("%b %d %H:%M:%S %Y %Z", "%Y%m%d%H%M%SZ"):
            try:
                parsed = datetime.strptime(value, fmt)
                return parsed.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        return None

    @staticmethod
    def _is_weak_cipher(name: str | None, bits: int | None) -> bool:
        if not name:
            return False
        upper = name.upper()
        weak_markers = ("RC4", "3DES", "DES", "NULL", "MD5", "EXP", "EXPORT", "RC2", "IDEA", "SEED")
        if bits is not None and bits < 128:
            return True
        return any(marker in upper for marker in weak_markers)

    @staticmethod
    def _parse_certificate_binary(cert_binary: bytes | None) -> dict[str, Any]:
        if not cert_binary:
            return {}
        try:
            cert = x509.load_der_x509_certificate(cert_binary, default_backend())
        except Exception:
            return {}

        subject = ", ".join(f"{attr.oid._name or attr.oid.dotted_string}={attr.value}" for attr in cert.subject)
        issuer = ", ".join(f"{attr.oid._name or attr.oid.dotted_string}={attr.value}" for attr in cert.issuer)
        san_values: list[str] = []
        try:
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            san_values = [name for name in ext.value.get_values_for_type(x509.DNSName)]
        except Exception:
            san_values = []

        not_before = getattr(cert, "not_valid_before_utc", None)
        not_after = getattr(cert, "not_valid_after_utc", None)
        if not not_before:
            not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
        if not not_after:
            not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)

        return {
            "subject": subject,
            "issuer": issuer,
            "san": san_values,
            "not_before": not_before,
            "not_after": not_after,
        }
