from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding

class X509Certificate():
    def __init__(self, cert):
        self.serial_nr = str(cert.serial_number)
        self.fingerprint = str(self.fingerprint)
        self.issuer = str(self.issuer)
        self.start = str(self.start)
        self.end = str(self.end)
        self.public_bytes = str(self.public_bytes)
        self.subject = str(self.subject)

class Policy():
    pass

class Ownership():
    pass