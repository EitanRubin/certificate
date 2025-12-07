from fastapi import FastAPI
from fastapi.responses import PlainTextResponse
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


app = FastAPI(title="Certificate Service")


def create_self_signed_cert(common_name: str) -> tuple[str, str]:
    """
    Create a self-signed X.509 certificate and private key (PEM strings).
    Compatible with OpenSSL.
    """

    # 1. Generate private key (RSA 2048)
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # 2. Build subject & issuer (same for self-signed)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IL"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Python CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )

    # 3. Certificate validity period
    utc_now = datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(utc_now)
        .not_valid_after(utc_now + timedelta(days=365))  # 1 year
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .sign(private_key=key, algorithm=hashes.SHA256())
    )

    # 4. Convert to PEM
    cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),  # no password
    ).decode()

    return cert_pem, key_pem


@app.get("/cert", response_class=PlainTextResponse)
def get_cert(cn: str = "example.com"):
    """
    Return a self-signed certificate + private key in PEM format.
    Use ?cn=some.name to customize the Common Name.
    """
    cert_pem, key_pem = create_self_signed_cert(cn)
    # Joined as one text response; you can split them if you prefer JSON
    return cert_pem + "\n" + key_pem
