from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding

class X509Certificate():
    def __init__(self, cert):
        self.serial_nr = str(cert.serial_number)
        self.fingerprint = str(cert.fingerprint)
        self.issuer = str(cert.issuer)
        self.start = str(cert.start)
        self.end = str(cert.end)
        self.public_bytes = str(cert.public_bytes)
        self.subject = str(cert.subject)

class Policy():
    pass

class Ownership():
    pass