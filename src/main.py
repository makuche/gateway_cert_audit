"""
TODO: Some policy names are not returned yet! see sample.json, some policies
lists are empty!
Some certificates return an ANSI error, probably because there is some weird non-
utf character in one of the certificate attributes. check which ones fail here
and implement proper exception handling


Backlog:
- possibility to print out all certificates which expire in next 3 months
  (maybe excluding already expired certificates, since they might not
   be in use anymore). Color-code
"""
 
# C:\Dev\gateway-provider\version\policies\zone\policy-zone\policy-zone_ENV.env\some-hash-value\
 
from collections import defaultdict
from xml.dom import minidom
from OpenSSL.crypto import load_certificate
from OpenSSL.crypto import FILETYPE_PEM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from datetime import datetime, date, timedelta
from dateutil import relativedelta
from pathlib import Path
import os
import zipfile
import json
import re
import argparse
 
from cert import X509Certificate
 
PATH = Path().cwd().parent.parent.parent / "git/axway"
CERTIFICATES = defaultdict(list)
PARSING_ERRORS = 0

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Collect certificate data.")
    parser.add_argument(
        "--repository_path",
        type=str,
        default="C:\\Dev\\axway",
        help="Path to the axway git repository on your machine."
        )
    return parser.parse_args()

def get_env_file_paths(repository_path):
    """
    Returns all environment (.env) file paths within the given repository.
    """
    if not isinstance(repository_path, Path):
        raise TypeError("repository base path should be of type Path.")
    env_file_paths = [f for f in repository_path.rglob("*.env")]
    print(f"Found {len(env_file_paths)} environment files! Parsing certificates now...")
    return env_file_paths
 
def read_cert_store_file_content(env_file_path):
    """
    For given .env file path, return the content of the CertStore XML file.
    """
    with zipfile.ZipFile(env_file_path, "r") as f:
        zip_contents = f.namelist()
        pattern = ".*CertStore-.*?\.xml"
        cert_store_relative_path = get_cert_store_relative_path(zip_contents, pattern)
        with f.open(cert_store_relative_path, "r") as cert_store:
            return cert_store.read().decode("utf-8", errors="ignore")
 
def get_cert_store_relative_path(zip_contents, pattern):
    """
    Helper function to find CertStore Path
    """
    return [s for s in zip_contents if re.match(pattern, s)][0]
 
def parse_all_certificates_from_xml_file_string(
    xml_string, certificates, policy_name, environment):
   
    # Parse xml string into a DOM
    dom = minidom.parseString(xml_string)
    models = dom.getElementsByTagName('entity')
   
    for model in models:
        if model.attributes['type'].value == 'Certificate':
            cert_from_xml = get_certificate_info_from_xml_node(model, certificates)
            if cert_from_xml is None:
                continue
            else:
                attributes, cert_alias = cert_from_xml
            if attributes["serial_nr"] not in certificates:
                certificates[attributes["serial_nr"]] = {}
                certificates[
                    attributes["serial_nr"]]["attributes"] = attributes
                certificates[attributes["serial_nr"]]["policies"] = []
            else:
                certificates[attributes["serial_nr"]]["policies"].append(
                    (policy_name, environment, cert_alias))
       
def get_certificate_info_from_xml_node(model, certificates):
    cert_attributes = None
    cert_alias = None
    for child_node in model.childNodes:
        if child_node.attributes is None:
            continue
        current_name = child_node.attributes['name'].value
        if current_name == 'content':
            pem_value = child_node.childNodes[0].firstChild.nodeValue
            cert_attributes = parse_certificate_content(pem_value)
            if cert_attributes is None:
                return
            # else:
            #     if x509_cert["serial_nr"] not in certificates:
            #         certificates[x509_cert["serial_nr"]] = {}
            #         certificates[x509_cert["serial_nr"]]["cert_info"] = x509_cert
            #         certificates[x509_cert["serial_nr"]]["policies"] = {}
        elif current_name == 'dname':
            if cert_attributes is not None:
                cert_alias = child_node.childNodes[0].firstChild.nodeValue
 
    return cert_attributes, cert_alias
 
def parse_certificate_content(pem_value):
    pem_string = wrap_cert_to_pem_format(pem_value)
    try:
        certificate = load_certificate(FILETYPE_PEM, pem_string).to_cryptography()
    except ValueError:
        return None
    x509_cert = X509Certificate(certificate)
    return x509_cert.to_dict()
 
def wrap_cert_to_pem_format(cert_content):
    cert_content = cert_content.replace('\n','')
    cert_content = cert_content.replace('\r','')
    pem_cert = '-----BEGIN CERTIFICATE-----\n' + cert_content + '\n' + '-----END CERTIFICATE-----'
    return pem_cert
 
def save_as_json(certificates, file_name="sample.json"):
    with open("sample.json", "w") as f:
        json.dump(certificates, f, indent=4)
 
if __name__ == '__main__':

    args = parse_arguments()
    repository_path = Path(args.repository_path).resolve()
    certificates = {}
    env_file_paths = get_env_file_paths(repository_path)
 
    for env_file_path in env_file_paths:
        cert_store_string = read_cert_store_file_content(env_file_path)
        env_path = env_file_path.__str__()
        policy_name = env_path.split('\\')[-2]
        environment = env_path.split('_')[-1].split('.')[0]
        print(env_file_path.__str__())
        print(env_file_path)
        print("policy:", policy_name)
        parse_all_certificates_from_xml_file_string(
            cert_store_string, certificates, policy_name, environment)
        #PARSING_ERRORS += errs
        save_as_json(certificates)
        #print("not parsed certs:", PARSING_ERRORS)

