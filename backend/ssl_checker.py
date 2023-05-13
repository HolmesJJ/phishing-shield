import re
import os
import csv
import sys
import idna
import time
import hashlib
import OpenSSL
import subprocess
import pandas as pd
import timeout_decorator

from OpenSSL import SSL
from socket import socket
from dateutil import parser
from cryptography import x509

PATHS = {
    "certs_dir": "certs/",
}


class CertInfo:

    def __init__(self, url, keep_cert=False):
        if not os.path.isdir(PATHS["certs_dir"]):
            os.makedirs(PATHS["certs_dir"])
        self._url = url.lstrip("https:").strip("/")
        self._cert = None
        self._cert_chain = None
        self._cert_name = hashlib.sha256(url.encode("utf-8")).hexdigest() + ".crt"
        self._results = {"Url": url}
        self._cert_file_path = PATHS["certs_dir"] + self._cert_name
        self._keep_cert = keep_cert

    @staticmethod
    def _load_from_directory(path):
        values = []
        for root, _, files in os.walk(path):
            files = [f for f in files if not f[0] == '.']
            for f in files:
                with open(os.path.join(root, f)) as infile:
                    for item in infile.readlines():
                        values.append(item.strip('\n'))
        return values

    def get_info(self, convert_to_df=False):
        start = time.perf_counter()
        res = self._get_cert()
        if res:
            res = self._download_cert(self._cert_file_path)
        response_time = time.perf_counter() - start
        if res:
            res = self._get_cert_fingerprint()
        if res:
            res = self._get_cert_text()
        if res:
            res = self._get_signature_algorithm()
        if res:
            res = self._get_public_key_algorithm()
        if res:
            res = self._get_public_key_length()
        if res:
            res = self._get_cert_info(response_time)
        if not self._keep_cert and os.path.exists(self._cert_file_path):
            os.remove(self._cert_file_path)
        if convert_to_df:
            return self._convert_cert_info()
        else:
            return self._results

    def _get_cert(self):
        sock = None
        sock_ssl = None
        try:
            sock = self._connect_socket()
            if sock is not None:
                sock_ssl = self._connect_ssl(sock)
            return True
        except (Exception,):
            return False
        finally:
            flag = sock_ssl is not None and sock is not None
            if sock_ssl is not None:
                sock_ssl.close()
            if sock is not None:
                sock.close()
            return flag

    def _get_openssl_command(self, cmds, regular=None):
        result = {}
        for key, cmd in cmds.items():
            try:
                cmd = '{0} {1}'.format(cmd, self._cert_file_path)
                proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                buff = proc.communicate()[0].decode()
                if regular is not None:
                    str_item = re.findall(regular, buff)
                    if len(str_item) > 1:
                        result[key] = []
                        for i in range(len(str_item)):
                            result[key].append(str_item[i])
                    elif len(str_item) == 1:
                        result[key] = str_item[0].replace(':', '')
                else:
                    str_item = buff
                    result[key] = str_item
            except (Exception,):
                return False
        self._results.update(result)
        return True

    def _get_cert_fingerprint(self):
        try:
            with open(self._cert_file_path, 'w+') as output_file:
                if sys.version_info[0] >= 3:
                    output_file.write((OpenSSL.crypto.dump_certificate(
                        OpenSSL.crypto.FILETYPE_PEM, self._cert_chain[0]).decode('utf-8')))
                else:
                    output_file.write((OpenSSL.crypto.dump_certificate(
                        OpenSSL.crypto.FILETYPE_PEM, self._cert_chain[0])))
        except (Exception,):
            return False
        cmds = {
            "MD5": "openssl x509 -fingerprint -md5 -in",
            "SHA1": "openssl x509 -fingerprint -sha1 -in",
            "SHA-256": "openssl x509 -fingerprint -sha256 -in",
        }
        regular = "Fingerprint=(.*)\n"
        if not self._get_openssl_command(cmds, regular):
            return False
        return True

    def _get_cert_text(self):
        try:
            with open(self._cert_file_path, 'w+') as output_file:
                if sys.version_info[0] >= 3:
                    output_file.write((OpenSSL.crypto.dump_certificate(
                        OpenSSL.crypto.FILETYPE_PEM, self._cert_chain[0]).decode('utf-8')))
                else:
                    output_file.write((OpenSSL.crypto.dump_certificate(
                        OpenSSL.crypto.FILETYPE_PEM, self._cert_chain[0])))
        except (Exception,):
            return False
        cmds = {
            "Text": "openssl x509 -text -in"
        }
        if not self._get_openssl_command(cmds):
            return False
        return True

    def _get_signature_algorithm(self):
        try:
            with open(self._cert_file_path, 'w+') as output_file:
                if sys.version_info[0] >= 3:
                    output_file.write((OpenSSL.crypto.dump_certificate(
                        OpenSSL.crypto.FILETYPE_PEM, self._cert_chain[0]).decode('utf-8')))
                else:
                    output_file.write((OpenSSL.crypto.dump_certificate(
                        OpenSSL.crypto.FILETYPE_PEM, self._cert_chain[0])))
        except (Exception,):
            return False
        cmds = {
            "Signature_Algorithm": "openssl x509 -text -in"
        }
        regular = "Signature Algorithm: (.*?)[,\\s]"
        if not self._get_openssl_command(cmds, regular):
            return False
        return True

    def _get_public_key_algorithm(self):
        try:
            with open(self._cert_file_path, 'w+') as output_file:
                if sys.version_info[0] >= 3:
                    output_file.write((OpenSSL.crypto.dump_certificate(
                        OpenSSL.crypto.FILETYPE_PEM, self._cert_chain[0]).decode('utf-8')))
                else:
                    output_file.write((OpenSSL.crypto.dump_certificate(
                        OpenSSL.crypto.FILETYPE_PEM, self._cert_chain[0])))
        except (Exception,):
            return False
        cmds = {
            "Public_Key_Algorithm": "openssl x509 -text -in"
        }
        regular = "Public Key Algorithm: (.*?)[,\\s]"
        if not self._get_openssl_command(cmds, regular):
            return False
        return True

    def _get_public_key_length(self):
        try:
            with open(self._cert_file_path, 'w+') as output_file:
                if sys.version_info[0] >= 3:
                    output_file.write((OpenSSL.crypto.dump_certificate(
                        OpenSSL.crypto.FILETYPE_PEM, self._cert_chain[0]).decode('utf-8')))
                else:
                    output_file.write((OpenSSL.crypto.dump_certificate(
                        OpenSSL.crypto.FILETYPE_PEM, self._cert_chain[0])))
        except (Exception,):
            return False
        cmds = {
            "Public_Key_Length": "openssl x509 -text -in"
        }
        regular = "Public-Key: (.*)\n"
        if not self._get_openssl_command(cmds, regular):
            return False
        return True

    @timeout_decorator.timeout(10)
    def _connect_socket(self, port=443):
        try:
            sock = socket()
            sock.setblocking(True)
            sock.connect((self._url, port), )
            return sock
        except (Exception,):
            return None

    @timeout_decorator.timeout(10)
    def _connect_ssl(self, sock):
        try:
            ctx = SSL.Context(SSL.SSLv23_METHOD)
            ctx.check_hostname = False
            ctx.verify_mode = SSL.VERIFY_NONE
            sock_ssl = SSL.Connection(ctx, sock)
            sock_ssl.set_tlsext_host_name(idna.encode(self._url))
            sock_ssl.set_connect_state()
            sock_ssl.do_handshake()
            self._cert = sock_ssl.get_peer_certificate()
            self._cert_chain = sock_ssl.get_peer_cert_chain()
            return sock_ssl
        except (Exception,):
            return None

    def _download_cert(self, cert_file_path):
        try:
            result = {}
            temp_cert_name = cert_file_path
            with open(temp_cert_name, "w+") as output_file:
                if sys.version_info[0] >= 3:
                    output_file.write((OpenSSL.crypto.dump_certificate(
                        OpenSSL.crypto.FILETYPE_PEM, self._cert_chain[0]).decode("utf-8").strip()))
                else:
                    output_file.write((OpenSSL.crypto.dump_certificate(
                        OpenSSL.crypto.FILETYPE_PEM, self._cert_chain[0])))
            result["Cert"] = self._cert_name
            self._results.update(result)
            return True
        except (Exception,):
            return False

    def _get_cert_info(self, response_time):
        result = {"Response_Time": response_time}
        try:
            issuer = self._cert.get_issuer()
            subject = self._cert.get_subject()
            """Issuer"""
            result["Issuer"] = {}
            result["Issuer"]["Count"] = len(issuer.get_components())
            issuer_content = ""
            for item in issuer.get_components():
                if item[0].decode("utf-8").strip() == "C":
                    result["Issuer"]["Country"] = item[1].decode("utf-8")
                if item[0].decode().strip().strip() == "ST":
                    result["Issuer"]["State_Province"] = item[1].decode("utf-8")
                if item[0].decode("utf-8").strip() == "O":
                    result["Issuer"]["Organization"] = item[1].decode("utf-8")
                if item[0].decode("utf-8").strip() == "OU":
                    result["Issuer"]["Organizational_Unit"] = item[1].decode("utf-8")
                if item[0].decode("utf-8").strip() == "CN":
                    result["Issuer"]["Common_Name"] = item[1].decode("utf-8")
                if item[0].decode("utf-8").strip() == "L":
                    result["Issuer"]["Location"] = item[1].decode("utf-8")
                issuer_content = issuer_content + item[1].decode("utf-8")
            if issuer.emailAddress:
                result["Issuer"]["Email_Address"] = issuer.emailAddress
                issuer_content = issuer_content + issuer.emailAddress
            result["Issuer"]["Length"] = len(issuer_content)
            result["Issuer"]["All"] = issuer
            """Subject"""
            result["Subject"] = {}
            result["Subject"]["Count"] = len(subject.get_components())
            subject_content = ""
            for item in subject.get_components():
                if item[0].decode("utf-8").strip() == "C":
                    result["Subject"]["Country"] = item[1].decode("utf-8")
                if item[0].decode("utf-8").strip() == "ST":
                    result["Subject"]["State_Province"] = item[1].decode("utf-8")
                if item[0].decode("utf-8").strip() == "O":
                    result["Subject"]["Organization"] = item[1].decode("utf-8")
                if item[0].decode("utf-8").strip() == "OU":
                    result["Subject"]["Organizational_Unit"] = item[1].decode("utf-8")
                if item[0].decode("utf-8").strip() == "CN":
                    result["Subject"]["Common_Name"] = item[1].decode("utf-8")
                if item[0].decode("utf-8").strip() == "L":
                    result["Subject"]["Location"] = item[1].decode("utf-8")
                subject_content = subject_content + item[1].decode("utf-8")
            if subject.emailAddress:
                result["Subject"]["Email_Address"] = subject.emailAddress
                subject_content = subject_content + subject.emailAddress
            result["Subject"]["Length"] = len(subject_content)
            result["Subject"]["All"] = subject
            """Validity"""
            not_before = parser.parse(self._cert.get_notBefore().decode("utf-8"))
            result["Not_Before"] = str(not_before.strftime("%Y-%m-%d %H:%M:%S")) + " UTC"
            not_after = parser.parse(self._cert.get_notAfter().decode("utf-8"))
            result["Not_After"] = str(not_after.strftime("%Y-%m-%d %H:%M:%S")) + " UTC"
            result['Validity_Days'] = (not_after - not_before).days
            result["Is_Expired"] = str(self._cert.has_expired())
            """Extension"""
            result["Extension"] = {}
            result["Extension"]["Count"] = self._cert.get_extension_count()
            for i in range(self._cert.get_extension_count()):
                if self._cert.get_extension(i).get_short_name().decode("utf-8").strip() == "basicConstraints":
                    basic_constraints = self._cert.to_cryptography().extensions.get_extension_for_class(
                        x509.BasicConstraints).value.ca
                    result["Extension"]["CA"] = str(basic_constraints)
                if self._cert.get_extension(i).get_short_name().decode("utf-8").strip() == "subjectAltName":
                    subject_alt_names = self._cert.to_cryptography().extensions.get_extension_for_class(
                        x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
                    result["Extension"]["Subject_Alt_Names"] = subject_alt_names
                if self._cert.get_extension(i).get_short_name().decode("utf-8").strip() == "certificatePolicies":
                    certificate_policies = self._cert.to_cryptography().extensions.get_extension_for_class(
                        x509.CertificatePolicies).value
                    oids = [policy.policy_identifier.dotted_string for policy in certificate_policies]
                    result["Extension"]["OIDs"] = oids
                if self._cert.get_extension(i).get_short_name().decode("utf-8").strip() == "authorityKeyIdentifier":
                    result["Extension"]["Authority_Key_Identifier"] = self._cert.get_extension(i)
                if self._cert.get_extension(i).get_short_name().decode("utf-8").strip() == "subjectKeyIdentifier":
                    result["Extension"]["Subject_Key_Identifier"] = self._cert.get_extension(i)
            result["Extension"]["All"] = self._cert.to_cryptography().extensions
        except (Exception,):
            return False
        self._results.update(result)
        return True

    def _convert_cert_info(self):
        cert_info = self._results
        return pd.DataFrame({
            "Url": [cert_info["Url"] if cert_info.get("Url") else ""],
            "Cert": [cert_info["Cert"] if cert_info.get("Cert") else ""],
            "Response_Time": [cert_info["Response_Time"] if cert_info.get("Response_Time") else ""],
            "MD5": [cert_info["MD5"] if cert_info.get("MD5") else ""],
            "SHA1": [cert_info["SHA1"] if cert_info.get("SHA1") else ""],
            "SHA-256": [cert_info["SHA-256"] if cert_info.get("SHA-256") else ""],
            "Text": [cert_info["Text"] if cert_info.get("Text") else ""],
            "Signature_Algorithm": [cert_info["Signature_Algorithm"] if cert_info.get("Signature_Algorithm") else ""],
            "Public_Key_Algorithm": [cert_info["Public_Key_Algorithm"] if
                                     cert_info.get("Public_Key_Algorithm") else ""],
            "Public_Key_Length": [cert_info["Public_Key_Length"] if cert_info.get("Public_Key_Length") else ""],
            "Issuer_Count": [cert_info["Issuer"]["Count"] if cert_info.get("Issuer", {}).get("Count") else ""],
            "Issuer_Country": [cert_info["Issuer"]["Country"] if cert_info.get("Issuer", {}).get("Country") else ""],
            "Issuer_State_Province": [cert_info["Issuer"]["State_Province"] if
                                      cert_info.get("Issuer", {}).get("State_Province") else ""],
            "Issuer_Organization": [cert_info["Issuer"]["Organization"] if
                                    cert_info.get("Issuer", {}).get("Organization") else ""],
            "Issuer_Organizational_Unit": [cert_info["Issuer"]["Organizational_Unit"] if
                                           cert_info.get("Issuer", {}).get("Organizational_Unit") else ""],
            "Issuer_Common_Name": [cert_info["Issuer"]["Common_Name"] if
                                   cert_info.get("Issuer", {}).get("Common_Name") else ""],
            "Issuer_Location": [cert_info["Issuer"]["Location"] if cert_info.get("Issuer", {}).get("Location") else ""],
            "Issuer_Email_Address": [cert_info["Issuer"]["Email_Address"] if
                                     cert_info.get("Issuer", {}).get("Email_Address") else ""],
            "Issuer_Length": [cert_info["Issuer"]["Length"] if cert_info.get("Issuer", {}).get("Length") else ""],
            "Issuer_All": [cert_info["Issuer"]["All"] if cert_info.get("Issuer", {}).get("All") else ""],
            "Subject_Count": [cert_info["Subject"]["Count"] if cert_info.get("Subject", {}).get("Count") else ""],
            "Subject_Country": [cert_info["Subject"]["Country"] if cert_info.get("Subject", {}).get("Country") else ""],
            "Subject_State_Province": [cert_info["Subject"]["State_Province"] if
                                       cert_info.get("Subject", {}).get("State_Province") else ""],
            "Subject_Organization": [cert_info["Subject"]["Organization"] if
                                     cert_info.get("Subject", {}).get("Organization") else ""],
            "Subject_Organizational_Unit": [cert_info["Subject"]["Organizational_Unit"] if
                                            cert_info.get("Subject", {}).get("Organizational_Unit") else ""],
            "Subject_Common_Name": [cert_info["Subject"]["Common_Name"] if
                                    cert_info.get("Subject", {}).get("Common_Name") else ""],
            "Subject_Location": [cert_info["Subject"]["Location"] if
                                 cert_info.get("Subject", {}).get("Location") else ""],
            "Subject_Email_Address": [cert_info["Subject"]["Email_Address"] if
                                      cert_info.get("Subject", {}).get("Email_Address") else ""],
            "Subject_Length": [cert_info["Subject"]["Length"] if cert_info.get("Subject", {}).get("Length") else ""],
            "Subject_All": [cert_info["Subject"]["All"] if cert_info.get("Subject", {}).get("All") else ""],
            "Not_Before": [cert_info["Not_Before"] if cert_info.get("Not_Before") else ""],
            "Not_After": [cert_info["Not_After"] if cert_info.get("Not_After") else ""],
            "Validity_Days": [cert_info["Validity_Days"] if cert_info.get("Validity_Days") else ""],
            "Is_Expired": [cert_info["Is_Expired"] if cert_info.get("Is_Expired") else ""],
            "Extension_Count": [cert_info["Extension"]["Count"] if cert_info.get("Extension", {}).get("Count") else ""],
            "Extension_CA": [cert_info["Extension"]["CA"] if cert_info.get("Extension", {}).get("CA") else ""],
            "Extension_Subject_Alt_Names": [str(cert_info["Extension"]["Subject_Alt_Names"]) if
                                            cert_info.get("Extension", {}).get("Subject_Alt_Names") else ""],
            "Extension_OIDs": [str(cert_info["Extension"]["OIDs"]) if
                               cert_info.get("Extension", {}).get("OIDs") else ""],
            "Extension_Authority_Key_Identifier": [cert_info["Extension"]["Authority_Key_Identifier"] if
                                                   cert_info.get("Extension", {}).get("Authority_Key_Identifier") else
                                                   ""],
            "Extension_Subject_Key_Identifier": [cert_info["Extension"]["Subject_Key_Identifier"] if
                                                 cert_info.get("Extension", {}).get("Subject_Key_Identifier") else ""],
            "Extension_All": [cert_info["Extension"]["All"] if cert_info.get("Extension", {}).get("All") else ""],
            "Extraction_Time": [str(round(time.time() * 1000))],
        })
