import datetime

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding

class X509Certificate():
    def __init__(self, cert):
        self.serial_nr = str(hex(cert.serial_number))[2:]
        self.serial_nr_decimal = str(cert.serial_number)
        self.fingerprint_SHA1 = str(cert.fingerprint(hashes.SHA1()).hex())
        self.fingerprint_SHA256 = str(cert.fingerprint(hashes.SHA256()).hex())
        self.fingerprint_SHA512 = str(cert.fingerprint(hashes.SHA512()).hex())
        self.issuer = str(cert.issuer.rfc4514_string())
        self.start = str(cert.not_valid_before)
        self.end = str(cert.not_valid_after)
        self.public_bytes = str(cert.public_bytes(Encoding.PEM))
        self.subject = str(cert.subject.rfc4514_string())

        self.expires_within_three_months = self.expiring_soon()
        self.expires_next_month = self.expiring_soon(time_delta=31)
        self.priv_key_on_hsm = None

    def to_dict(self):
        return vars(self)

    def expiring_soon(self, time_delta=90):
        now = datetime.datetime.now()
        end_datetime = datetime.datetime.strptime(
            self.end, "%Y-%m-%d %H:%M:%S"
        )
        if end_datetime < now:
            return "already expired"
        elif (now + datetime.timedelta(days=time_delta)) > end_datetime:
            return True
        else:
            return False
class Policy():
    pass

class Ownership():
    pass