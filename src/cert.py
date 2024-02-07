from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding

class X509Certificate():
    def __init__(self, cert):
        self.serial_nr = str(cert.serial_number)
        self.fingerprint = str(cert.fingerprint(hashes.SHA512().hex()))
        self.issuer = str(cert.issuer.rfc4514_string())
        self.start = str(cert.not_valid_before)
        self.end = str(cert.not_valid_after)
        self.public_bytes = str(cert.public_bytes(Encoding.PEM))
        self.subject = str(cert.subject.rfc4514_string())

    def to_dict(self):
        return vars(self)

    def is_valid(self):
        # TODO: Return start.end > current_datetime
        pass

    def expires_soon(self):
        # TODO: Returns true if either
            # 1) is_valid is true, or
            # 2) if (start.end - 3 months) < current_datetime
        pass
class Policy():
    pass

class Ownership():
    pass