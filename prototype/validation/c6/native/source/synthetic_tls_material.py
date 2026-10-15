"""Public deterministic C6 loopback-only test identities. Never persist a key.

The seed is PUBLIC test data, not a credential. Candidate launch passes the
derived in-memory leaf signing material through an anonymous inherited pipe.
Only certificates (public information) are written by this module.
"""
import datetime
import hashlib
import ipaddress
import json
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


PUBLIC_TEST_SEED = b"PushGo C6 PUBLIC loopback test identities 2026-10-15; never trust outside isolated staging"


def signing_material(label):
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(PUBLIC_TEST_SEED + b":" + label.encode()).digest())


def name(label):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "C6 loopback synthetic " + label)])


def certificate(label, ca_label, serial, is_ca=False, wrong_host=False):
    subject_key = signing_material(label)
    issuer_key = signing_material(ca_label)
    builder = (x509.CertificateBuilder().subject_name(name(label)).issuer_name(name(ca_label))
               .public_key(subject_key.public_key()).serial_number(serial)
               .not_valid_before(datetime.datetime(2026, 10, 1, tzinfo=datetime.timezone.utc))
               .not_valid_after(datetime.datetime(2027, 10, 1, tzinfo=datetime.timezone.utc))
               .add_extension(x509.BasicConstraints(ca=is_ca, path_length=0 if is_ca else None), critical=True)
               .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                    key_encipherment=False, data_encipherment=False, key_agreement=False,
                    key_cert_sign=is_ca, crl_sign=is_ca, encipher_only=False, decipher_only=False), critical=True))
    if not is_ca:
        hosts = ([x509.DNSName("c6-wrong.invalid")] if wrong_host else
                 [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))])
        builder = builder.add_extension(x509.SubjectAlternativeName(hosts), critical=False)
        builder = builder.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    return builder.sign(issuer_key, algorithm=None)


def leaf_pem_for_anonymous_pipe(label="leaf"):
    """Bytes are returned in memory only. Caller must not log or persist them."""
    if label not in ("leaf", "wrong-ca", "wrong-host", "wrong-pin"):
        raise ValueError("unknown C6 test leaf")
    return signing_material(label).private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def write_public_certificates(output):
    output.mkdir(parents=True, exist_ok=True)
    certificates = {"ca": certificate("ca", "ca", 1001, is_ca=True),
                    "other-ca": certificate("other-ca", "other-ca", 1002, is_ca=True),
                    "leaf": certificate("leaf", "ca", 1011),
                    "wrong-ca": certificate("wrong-ca", "other-ca", 1012),
                    "wrong-host": certificate("wrong-host", "ca", 1013, wrong_host=True),
                    "wrong-pin": certificate("wrong-pin", "ca", 1014)}
    identity = {}
    for label, value in certificates.items():
        der = value.public_bytes(serialization.Encoding.DER)
        (output / (label + ".der")).write_bytes(der)
        (output / (label + ".pem")).write_bytes(value.public_bytes(serialization.Encoding.PEM))
        identity[label] = {"der_sha256": hashlib.sha256(der).hexdigest(), "serial": value.serial_number}
    (output / "public-identities.json").write_text(json.dumps({"public_seed": PUBLIC_TEST_SEED.decode(),
          "test_trust_only": True, "private_material_persisted": False, "identities": identity}, indent=2))
    return identity


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--public-output", type=Path, required=True)
    arguments = parser.parse_args()
    print(json.dumps(write_public_certificates(arguments.public_output), indent=2))
