import zipfile
import json
import re
import argparse
import multiprocessing

from multiprocessing import Pool
from xml.dom import minidom
from OpenSSL.crypto import load_certificate
from OpenSSL.crypto import FILETYPE_PEM
from pathlib import Path
 
from cert import X509Certificate
 

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
    print(f"Found {len(env_file_paths)} environment files!" +
           "Parsing certificates now...")
    return env_file_paths
 
def read_cert_store_file_content(env_file_path):
    """
    For given .env file path, return the content of the CertStore XML file.
    """
    with zipfile.ZipFile(env_file_path, "r") as f:
        zip_contents = f.namelist()
        pattern = ".*CertStore-.*?\.xml"
        cert_store_relative_path = get_cert_store_relative_path(
            zip_contents, pattern)
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
            cert_from_xml = get_certificate_info_from_xml_node(
                model, certificates)
            if cert_from_xml is None:
                print(f"WARNING: Skipping certificate from {policy_name} " +
                      "due to PEM decoding error.")
                continue
            else:
                attributes, cert_alias = cert_from_xml
            if attributes["fingerprint_SHA512"] not in certificates:
                cert = certificates[attributes["fingerprint_SHA512"]] = {}
                cert["attributes"] = attributes
                cert["policies"] = [(environment, policy_name, cert_alias)]
            else:
                certificates[attributes["fingerprint_SHA512"]]["policies"] \
                    .append((environment, policy_name, cert_alias))
       
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
        elif current_name == 'dname':
            if cert_attributes is not None:
                cert_alias = child_node.childNodes[0].firstChild.nodeValue
        elif current_name == 'storeType':
            if cert_attributes is not None:
                cert_attributes["store_type"] = child_node.childNodes[0] \
                    .firstChild.nodeValue
    return cert_attributes, cert_alias
 
def parse_certificate_content(pem_value):
    pem_string = wrap_cert_to_pem_format(pem_value)
    try:
        certificate = load_certificate(
            FILETYPE_PEM, pem_string).to_cryptography()
    except ValueError:
        return None
    x509_cert = X509Certificate(certificate)
    return x509_cert.to_dict()
 
def wrap_cert_to_pem_format(cert_content):
    cert_content = cert_content.replace('\n','')
    cert_content = cert_content.replace('\r','')
    pem_cert = '-----BEGIN CERTIFICATE-----\n' + \
        cert_content + '\n' + '-----END CERTIFICATE-----'
    return pem_cert
 
def save_as_json(certificates, file_name="sample.json"):
    with open("sample.json", "w") as f:
        json.dump(certificates, f, indent=4, sort_keys=True)
 
def process_env_file(env_file_path):
    try:
        cert_store_string = read_cert_store_file_content(env_file_path)
        env_path = str(env_file_path)
        policy_name = env_path.split('\\')[-2]
        environment = env_path.split('_')[-1].split('.')[0]
        certificates = {}
        parse_all_certificates_from_xml_file_string(
            cert_store_string, certificates, policy_name, environment
        )
        return certificates
    except Exception as e:
        print(f"Error processing env file {env_file_path}")
        return 0

if __name__ == '__main__':

    args = parse_arguments()
    repository_path = Path(args.repository_path).resolve()
    certificates = {}
    env_file_paths = get_env_file_paths(repository_path)
 
    num_processes = multiprocessing.cpu_count()
    with Pool(num_processes) as pool:
        results = pool.map(process_env_file, env_file_paths)

    all_certificates = {}
    for cert_data in results:
        for fingerprint, cert_info in cert_data.items():
            if fingerprint not in all_certificates:
                all_certificates[fingerprint] = cert_info
            else:
                all_certificates[fingerprint]['policies'].extend(
                    cert_info['policies']
                )
    save_as_json(all_certificates)
