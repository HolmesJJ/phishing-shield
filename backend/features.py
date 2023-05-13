import re
import os
import ast
import math
import pandas as pd
import pickle
import string
import tldextract

from collections import Counter
from Levenshtein import distance
from gibberish_detector.gib_detect_train import avg_transition_prob

FEATURE_PATHS = {
    "feature_columns": "feature_columns.pkl",
    "tlds_dir": "tlds/",
    "tiny_urls_dir": "tiny_urls/",
    "free_issuers_dir": "free_issuers/",
    "misc_keywords_dir": "misc_keywords/",
    "suspicious_tlds_dir": "suspicious_tlds/",
    "suspicious_keywords_dir": "suspicious_keywords/",
    "cert_policies": "cert_policies/cert_policies.csv",
    "extension_attributes": "extension_attributes/extension_attributes.csv",
    "gib_model": "gibberish_detector/gib_model.pki",
}

'''
-1: missing values
 1: true
 0: false
'''


class PhishFeatures:

    def __init__(self):
        self._tlds = self._load_from_directory(FEATURE_PATHS["tlds_dir"])
        self._tiny_urls = self._load_from_directory(FEATURE_PATHS["tiny_urls_dir"])
        self._free_issuers = self._load_from_directory(FEATURE_PATHS["free_issuers_dir"])
        self._misc_keywords = self._load_from_directory(FEATURE_PATHS["misc_keywords_dir"])
        self._suspicious_tlds = self._load_from_directory(FEATURE_PATHS["suspicious_tlds_dir"])
        self._suspicious_keywords = self._load_from_directory(FEATURE_PATHS["suspicious_keywords_dir"])
        self._gib_model = pickle.load(open(FEATURE_PATHS["gib_model"], "rb"))

    @staticmethod
    def _load_from_directory(path):
        values = []
        for root, _, files in os.walk(path):
            files = [f for f in files if not f[0] == "."]
            for f in files:
                with open(os.path.join(root, f)) as infile:
                    for item in infile.readlines():
                        values.append(item.strip("\n"))
        return values

    @staticmethod
    def _fqdn_parts(fqdn):
        parts = tldextract.extract(fqdn)
        result = {"subdomain": parts.subdomain,
                  "domain": parts.domain,
                  "tld": parts.suffix}
        return result

    @staticmethod
    def _longest_common_substring(str_a, str_b):
        len_a = len(str_a)
        len_b = len(str_b)
        length_table = [[0] * (len_b + 1) for _ in range(len_a + 1)]
        result = 0
        for i in range(0, len_a):
            for j in range(0, len_b):
                if str_a[i] == str_b[j]:
                    length_table[i + 1][j + 1] = length_table[i][j] + 1
                    result = max(result, length_table[i + 1][j + 1])
        return result

    def _is_same_strings(self, str_a, str_b, threshold=None):
        if threshold is None:
            return str_a == str_b
        common_len = self._longest_common_substring(str_a, str_b)
        min_len = min(len(str_a), len(str_b))
        if common_len > threshold:
            return True
        else:
            return str_a == str_b

    @staticmethod
    def _is_ip(address):
        parts = address.split(".")
        if len(parts) != 4:
            return False
        for part in parts:
            if not part.isdigit():
                return False
            num = int(part)
            if num < 0 or num > 255:
                return False
        return True

    @staticmethod
    def _convert_to_attributes(extension_attributes, extension_all, extension_count):
        attributes = {}
        for i, attribute in enumerate(extension_attributes):
            attributes[attribute] = i
        attribute_contents = [""] * len(extension_attributes)
        extensions = extension_all[len("<Extensions(["):][:-len("])>"):].split(", <Extension(")
        extensions = [extension if extension.startswith("<Extension(") else "<Extension(" + extension
                      for extension in extensions]
        if extension_count != len(extensions):
            print(str(extension_count) + "." + str(len(extensions)))
        for extension in extensions:
            regular = "name=(.*?)\)>"
            names = re.findall(regular, extension)
            if len(names) > 0 and names[0] in attributes:
                attribute_contents[attributes[names[0]]] = extension
            else:
                print(extension)
        return attribute_contents

    def _extract_extension_attributes(self, sample):
        extension_attributes = list(pd.read_csv(FEATURE_PATHS["extension_attributes"], header=None)[0].values)
        extensions = []
        for i, row in sample.iterrows():
            extension_count = row["Extension_Count"]
            extension_all = row["Extension_All"]
            if extension_count and extension_all:
                attributes = self._convert_to_attributes(extension_attributes, extension_all,
                                                         int(float(extension_count)))
                extensions.append(attributes)
            else:
                extensions.append([""] * len(extension_attributes))
        extensions_df = pd.DataFrame(extensions)
        extensions_df.columns = extension_attributes
        return extensions_df

    def compute_samples(self, path):
        sample = pd.read_csv(path, keep_default_na=False, index_col=False)
        sample = pd.concat([sample, self._extract_extension_attributes(sample)], axis=1)
        return sample

    def compute_features(self, sample):
        feature_columns = pickle.load(open(FEATURE_PATHS["feature_columns"], "rb"))
        features = pd.DataFrame(columns=feature_columns)
        signature_algorithm_features = self._fe_signature_algorithm(sample)
        for column in signature_algorithm_features.columns:
            if column in feature_columns:
                features[column] = signature_algorithm_features[column]
        public_key_algorithm_features = self._fe_public_key_algorithm(sample)
        for column in public_key_algorithm_features.columns:
            if column in feature_columns:
                features[column] = public_key_algorithm_features[column]
        public_key_length_features = self._fe_public_key_length(sample)
        for column in public_key_length_features.columns:
            if column in feature_columns:
                features[column] = public_key_length_features[column]
        """Issuer Subject"""
        features["Is_Issuer_Subject_Same"] = self._fe_is_issuer_subject_same(sample)
        features["Is_Issuer_Subject_Country_Same"] = self._fe_is_issuer_subject_country_same(sample)
        features["Is_Issuer_Subject_State_Province_Same"] = self._fe_is_issuer_subject_state_province_same(sample)
        features["Is_Issuer_Subject_Organization_Same"] = self._fe_is_issuer_subject_organization_same(sample)
        features["Is_Issuer_Subject_Organizational_Unit_Same"] = self._fe_is_issuer_subject_organizational_unit_same(
            sample)
        features["Is_Issuer_Subject_Common_Name_Same"] = self._fe_is_issuer_subject_common_name_same(sample)
        features["Is_Issuer_Subject_Location_Same"] = self._fe_is_issuer_subject_location_same(sample)
        features["Is_Issuer_Subject_Email_Address_Same"] = self._fe_is_issuer_subject_email_address_same(sample)
        """Issuer"""
        features["Issuer_Count"] = self._fe_issuer_count(sample)
        features["Issuer_Common_Name_Entropy"] = self._fe_issuer_common_name_entropy(sample)
        features["Issuer_Common_Name_GIB"] = self._fe_issuer_common_name_gib(sample)
        issuer_country_value_features = self._fe_issuer_country_value(sample)
        for column in issuer_country_value_features.columns:
            if column in feature_columns:
                features[column] = issuer_country_value_features[column]
        issuer_state_province_value_features = self._fe_issuer_state_province_value(sample)
        for column in issuer_state_province_value_features.columns:
            if column in feature_columns:
                features[column] = issuer_state_province_value_features[column]
        issuer_organization_value_features = self._fe_issuer_organization_value(sample)
        for column in issuer_organization_value_features.columns:
            if column in feature_columns:
                features[column] = issuer_organization_value_features[column]
        issuer_organizational_unit_value_features = self._fe_issuer_organizational_unit_value(sample)
        for column in issuer_organizational_unit_value_features.columns:
            if column in feature_columns:
                features[column] = issuer_organizational_unit_value_features[column]
        issuer_common_name_value_features = self._fe_issuer_common_name_value(sample)
        for column in issuer_common_name_value_features.columns:
            if column in feature_columns:
                features[column] = issuer_common_name_value_features[column]
        issuer_location_value_features = self._fe_issuer_location_value(sample)
        for column in issuer_location_value_features.columns:
            if column in feature_columns:
                features[column] = issuer_location_value_features[column]
        issuer_email_address_value_features = self._fe_issuer_email_address_value(sample)
        for column in issuer_email_address_value_features.columns:
            if column in feature_columns:
                features[column] = issuer_email_address_value_features[column]
        features["Has_Issuer_Country"] = self._fe_has_issuer_country(sample)
        features["Has_Issuer_State_Province"] = self._fe_has_issuer_state_province(sample)
        features["Has_Issuer_Organization"] = self._fe_has_issuer_organization(sample)
        features["Has_Issuer_Organizational_Unit"] = self._fe_has_issuer_organizational_unit(sample)
        features["Has_Issuer_Common_Name"] = self._fe_has_issuer_common_name(sample)
        features["Has_Issuer_Location"] = self._fe_has_issuer_location(sample)
        features["Has_Issuer_Email_Address"] = self._fe_has_issuer_email_address(sample)
        features["Has_Tld_In_Issuer_Common_Name"] = self._fe_has_tld_in_issuer_common_name(sample)
        features["Has_Suspicious_Tld_In_Issuer_CN"] = self._fe_has_suspicious_tld_in_issuer_cn(sample)
        features["Has_Suspicious_KWs_In_Issuer_CN"] = self._fe_has_suspicious_kws_in_issuer_cn(sample)
        features["Has_Misc_KWs_In_Issuer_CN"] = self._fe_has_misc_kws_in_issuer_cn(sample)
        features["Suspicious_KWs_Similarity_In_Issuer_CN"] = self._fe_suspicious_kws_similarity_in_issuer_cn(sample)
        features["Is_Issuer_Common_Name_Ip"] = self._fe_is_issuer_common_name_ip(sample)
        features["Is_Issuer_Only_Common_Name"] = self._fe_is_issuer_only_common_name(sample)
        features["Is_Free"] = self._fe_is_free(sample)
        features["Issuer_Length"] = self._fe_issuer_length(sample)
        """Subject"""
        features["Subject_Count"] = self._fe_subject_count(sample)
        features["Subject_Common_Name_Entropy"] = self._fe_subject_common_name_entropy(sample)
        features["Subject_Common_Name_GIB"] = self._fe_subject_common_name_gib(sample)
        subject_country_value_features = self._fe_subject_country_value(sample)
        for column in subject_country_value_features.columns:
            if column in feature_columns:
                features[column] = subject_country_value_features[column]
        subject_state_province_value_features = self._fe_subject_state_province_value(sample)
        for column in subject_state_province_value_features.columns:
            if column in feature_columns:
                features[column] = subject_state_province_value_features[column]
        features["Has_Subject_Country"] = self._fe_has_subject_country(sample)
        features["Has_Subject_State_Province"] = self._fe_has_subject_state_province(sample)
        features["Has_Subject_Organization"] = self._fe_has_subject_organization(sample)
        features["Has_Subject_Organizational_Unit"] = self._fe_has_subject_organizational_unit(sample)
        features["Has_Subject_Common_Name"] = self._fe_has_subject_common_name(sample)
        features["Has_Subject_Location"] = self._fe_has_subject_location(sample)
        features["Has_Subject_Email_Address"] = self._fe_has_subject_email_address(sample)
        features["Has_Tld_In_Subject_Common_Name"] = self._fe_has_tld_in_subject_common_name(sample)
        features["Has_Suspicious_Tld_In_Subject_CN"] = self._fe_has_suspicious_tld_in_subject_cn(sample)
        features["Has_Suspicious_KWs_In_Subject_CN"] = self._fe_has_suspicious_kws_in_subject_cn(sample)
        features["Has_Misc_KWs_In_Subject_CN"] = self._fe_has_misc_kws_in_subject_cn(sample)
        features["Suspicious_KWs_Similarity_In_Subject_CN"] = self._fe_suspicious_kws_similarity_in_subject_cn(sample)
        features["Is_Subject_Common_Name_Ip"] = self._fe_is_subject_common_name_ip(sample)
        features["Is_Subject_Only_Common_Name"] = self._fe_is_subject_only_common_name(sample)
        features["Subject_Length"] = self._fe_subject_length(sample)
        """Validity"""
        features["Validity_Days"] = pd.to_numeric(sample["Validity_Days"])
        features["Is_Expired"] = self._fe_is_expired(sample)
        """Extension"""
        features["Extension_Count"] = pd.to_numeric(sample["Extension_Count"])
        features["CA"] = self._fe_ca(sample)
        features["Subject_Alt_Names_Count"] = self._fe_subject_alt_names_count(sample)
        features["OCSP_No_Check_Critical"] = self._fe_ocsp_no_check_critical(sample)
        features["TLS_Feature_Critical"] = self._fe_tls_feature_critical(sample)
        features["TLS_Feature_Features"] = self._fe_tls_feature_features(sample)
        features["Unknown_OID_Critical"] = self._fe_unknown_oid_critical(sample)
        unknown_oid_oid_features = self._fe_unknown_oid_oid(sample)
        for column in unknown_oid_oid_features.columns:
            if column in feature_columns:
                features[column] = unknown_oid_oid_features[column]
        unknown_oid_value_features = self._fe_unknown_oid_value(sample)
        for column in unknown_oid_value_features.columns:
            if column in feature_columns:
                features[column] = unknown_oid_value_features[column]
        features["Authority_Info_Access_Critical"] = self._fe_authority_info_access_critical(sample)
        authority_info_access_ocsp_features = self._fe_authority_info_access_ocsp(sample)
        for column in authority_info_access_ocsp_features.columns:
            if column in feature_columns:
                features[column] = authority_info_access_ocsp_features[column]
        authority_info_access_ca_issuers_features = self._fe_authority_info_access_ca_issuers(sample)
        for column in authority_info_access_ca_issuers_features.columns:
            if column in feature_columns:
                features[column] = authority_info_access_ca_issuers_features[column]
        features["Authority_Key_Identifier_Critical"] = self._fe_authority_key_identifier_critical(sample)
        authority_key_identifier_key_identifier_features = self._fe_authority_key_identifier_key_identifier(sample)
        for column in authority_key_identifier_key_identifier_features.columns:
            if column in feature_columns:
                features[column] = authority_key_identifier_key_identifier_features[column]
        authority_key_identifier_authority_cert_issuer_features = self._fe_authority_key_identifier_authority_cert_issuer(sample)
        for column in authority_key_identifier_authority_cert_issuer_features.columns:
            if column in feature_columns:
                features[column] = authority_key_identifier_authority_cert_issuer_features[column]
        authority_key_identifier_authority_cert_serial_number_features = self._fe_authority_key_identifier_authority_cert_serial_number(sample)
        for column in authority_key_identifier_authority_cert_serial_number_features.columns:
            if column in feature_columns:
                features[column] = authority_key_identifier_authority_cert_serial_number_features[column]
        features["Basic_Constraints_Critical"] = self._fe_basic_constraints_critical(sample)
        features["Basic_Constraints_CA"] = self._fe_basic_constraints_ca(sample)
        basic_constraints_path_length_features = self._fe_basic_constraints_path_length(sample)
        for column in basic_constraints_path_length_features.columns:
            if column in feature_columns:
                features[column] = basic_constraints_path_length_features[column]
        features["CRL_Distribution_Points_Critical"] = self._fe_crl_distribution_points_critical(sample)
        crl_distribution_points_value_features = self._fe_crl_distribution_points_value(sample)
        for column in crl_distribution_points_value_features.columns:
            if column in feature_columns:
                features[column] = crl_distribution_points_value_features[column]
        features["Certificate_Policies_Critical"] = self._fe_certificate_policies_critical(sample)
        features["Certificate_Policies_Value"] = self._fe_certificate_policies_value(sample)
        features["Extended_Key_Usage_Critical"] = self._fe_extended_key_usage_critical(sample)
        features["Extended_Key_Usage_Server_Auth"] = self._fe_extended_key_usage_server_auth(sample)
        features["Extended_Key_Usage_Client_Auth"] = self._fe_extended_key_usage_client_auth(sample)
        features["Extended_Key_Usage_Unknown_OID"] = self._fe_extended_key_usage_unknown_oid(sample)
        features["Extended_Key_Usage_OCSP_Signing"] = self._fe_extended_key_usage_ocsp_signing(sample)
        features["Extended_Key_Usage_Code_Signing"] = self._fe_extended_key_usage_code_signing(sample)
        features["Extended_Key_Usage_Email_Protection"] = self._fe_extended_key_usage_email_protection(sample)
        features["Extended_Key_Usage_Time_Stamping"] = self._fe_extended_key_usage_time_stamping(sample)
        features["Freshest_CRL_Critical"] = self._fe_freshest_crl_critical(sample)
        freshest_crl_value_features = self._fe_freshest_crl_value(sample)
        for column in freshest_crl_value_features.columns:
            if column in feature_columns:
                features[column] = freshest_crl_value_features[column]
        features["Issuer_Alt_Name_Critical"] = self._fe_issuer_alt_name_critical(sample)
        issuer_alt_name_value_features = self._fe_issuer_alt_name_value(sample)
        for column in issuer_alt_name_value_features.columns:
            if column in feature_columns:
                features[column] = issuer_alt_name_value_features[column]
        features["Key_Usage_Critical"] = self._fe_key_usage_critical(sample)
        features["Key_Usage_Digital_Signature"] = self._fe_key_usage_digital_signature(sample)
        features["Key_Usage_Content_Commitment"] = self._fe_key_usage_content_commitment(sample)
        features["Key_Usage_Key_Encipherment"] = self._fe_key_usage_key_encipherment(sample)
        features["Key_Usage_Data_Encipherment"] = self._fe_key_usage_data_encipherment(sample)
        features["Key_Usage_Key_Agreement"] = self._fe_key_usage_key_agreement(sample)
        features["Key_Usage_Key_Cert_Sign"] = self._fe_key_usage_key_cert_sign(sample)
        features["Key_Usage_Crl_Sign"] = self._fe_key_usage_crl_sign(sample)
        features["Key_Usage_Encipher_Only"] = self._fe_key_usage_encipher_only(sample)
        features["Key_Usage_Decipher_Only"] = self._fe_key_usage_decipher_only(sample)
        features["Signed_Certificate_Timestamp_List_Critical"] = self._fe_signed_certificate_timestamp_list_critical(
            sample)
        features["Signed_Certificate_Timestamp_List_Value"] = self._fe_signed_certificate_timestamp_list_value(sample)
        features["Subject_Alt_Name_Critical"] = self._fe_subject_alt_name_critical(sample)
        features["Subject_Alt_Name_Value"] = self._fe_subject_alt_name_value(sample)
        features["Subject_Directory_Attributes_Critical"] = self._fe_subject_directory_attributes_critical(sample)
        subject_directory_attributes_value_features = self._fe_subject_directory_attributes_value(sample)
        for column in subject_directory_attributes_value_features.columns:
            if column in feature_columns:
                features[column] = subject_directory_attributes_value_features[column]
        features["Subject_Key_Identifier_Critical"] = self._fe_subject_key_identifier_critical(sample)
        features["Is_Extended_Validated"] = self._fe_is_extended_validated(sample)
        features["Is_Organization_Validated"] = self._fe_is_organization_validated(sample)
        features["Is_Domain_Validated"] = self._fe_is_domain_validated(sample)
        features["Is_Individual_Validated"] = self._fe_is_individual_validated(sample)
        features["Is_Self_Signed"] = self._fe_is_self_signed(sample)
        features = features.fillna(0)
        return features

    @staticmethod
    def _fe_signature_algorithm(sample):
        feature = []
        for item in sample["Signature_Algorithm"]:
            extracted_item = ""
            if pd.notnull(item):
                extracted_elements = set()
                for element in item.split("', '"):
                    if "['" in element:
                        element = element[len("['"):]
                    if "']" in element:
                        element = element[:-len("']")]
                    extracted_elements.add(element)
                extracted_item = list(extracted_elements)[0]
            feature.append(extracted_item)
        signature_algorithm = pd.DataFrame(feature, columns=["Signature_Algorithm"])
        return pd.get_dummies(signature_algorithm["Signature_Algorithm"])

    @staticmethod
    def _fe_public_key_algorithm(sample):
        return pd.get_dummies(sample["Signature_Algorithm"])

    @staticmethod
    def _fe_public_key_length(sample):
        return pd.get_dummies(sample["Public_Key_Length"])

    """Issuer Subject"""

    def _fe_is_issuer_subject_same(self, sample):
        feature = []
        for i, row in sample.iterrows():
            if (self._is_same_strings(row["Issuer_Country"], row["Subject_Country"]) and
                    self._is_same_strings(row["Issuer_State_Province"], row["Subject_State_Province"]) and
                    self._is_same_strings(row["Issuer_Organization"], row["Subject_Organization"]) and
                    self._is_same_strings(row["Issuer_Organizational_Unit"], row["Subject_Organizational_Unit"]) and
                    self._is_same_strings(row["Issuer_Common_Name"], row["Subject_Common_Name"]) and
                    self._is_same_strings(row["Issuer_Location"], row["Subject_Location"]) and
                    self._is_same_strings(row["Issuer_Email_Address"], row["Subject_Email_Address"])):
                feature.append(1)
            else:
                feature.append(0)
        return feature

    def _fe_is_issuer_subject_country_same(self, sample):
        feature = []
        for i, row in sample.iterrows():
            if row["Issuer_Country"] == "" and row["Subject_Country"] == "":
                feature.append(-1)
            elif self._is_same_strings(row["Issuer_Country"], row["Subject_Country"]):
                feature.append(1)
            else:
                feature.append(0)
        return feature

    def _fe_is_issuer_subject_state_province_same(self, sample):
        feature = []
        for i, row in sample.iterrows():
            if row["Issuer_State_Province"] == "" and row["Subject_State_Province"] == "":
                feature.append(-1)
            elif self._is_same_strings(row["Issuer_State_Province"], row["Subject_State_Province"]):
                feature.append(1)
            else:
                feature.append(0)
        return feature

    def _fe_is_issuer_subject_organization_same(self, sample):
        feature = []
        for i, row in sample.iterrows():
            if row["Issuer_Organization"] == "" and row["Issuer_Organization"] == "":
                feature.append(-1)
            elif self._is_same_strings(row["Issuer_Organization"], row["Subject_Organization"]):
                feature.append(1)
            else:
                feature.append(0)
        return feature

    def _fe_is_issuer_subject_organizational_unit_same(self, sample):
        feature = []
        for i, row in sample.iterrows():
            if row["Issuer_Organizational_Unit"] == "" and row["Issuer_Organizational_Unit"] == "":
                feature.append(-1)
            elif self._is_same_strings(row["Issuer_Organizational_Unit"], row["Subject_Organizational_Unit"]):
                feature.append(1)
            else:
                feature.append(0)
        return feature

    def _fe_is_issuer_subject_common_name_same(self, sample):
        feature = []
        for i, row in sample.iterrows():
            if row["Issuer_Common_Name"] == "" and row["Issuer_Common_Name"] == "":
                feature.append(-1)
            elif self._is_same_strings(row["Issuer_Common_Name"], row["Subject_Common_Name"]):
                feature.append(1)
            else:
                feature.append(0)
        return feature

    def _fe_is_issuer_subject_location_same(self, sample):
        feature = []
        for i, row in sample.iterrows():
            if row["Issuer_Location"] == "" and row["Issuer_Location"] == "":
                feature.append(-1)
            elif self._is_same_strings(row["Issuer_Location"], row["Subject_Location"]):
                feature.append(1)
            else:
                feature.append(0)
        return feature

    def _fe_is_issuer_subject_email_address_same(self, sample):
        feature = []
        for i, row in sample.iterrows():
            if row["Issuer_Email_Address"] == "" and row["Issuer_Email_Address"] == "":
                feature.append(-1)
            elif self._is_same_strings(row["Issuer_Email_Address"], row["Subject_Email_Address"]):
                feature.append(1)
            else:
                feature.append(0)
        return feature

    """Issuer"""

    @staticmethod
    def _fe_issuer_count(sample):
        feature = []
        for i, row in sample.iterrows():
            count = 0
            if len(row["Issuer_Country"]) > 0:
                count += 1
            if len(row["Issuer_State_Province"]) > 0:
                count += 1
            if len(row["Issuer_Organization"]) > 0:
                count += 1
            if len(row["Issuer_Organizational_Unit"]) > 0:
                count += 1
            if len(row["Issuer_Common_Name"]) > 0:
                count += 1
            if len(row["Issuer_Country"]) > 0:
                count += 1
            if len(row["Issuer_Email_Address"]) > 0:
                count += 1
            feature.append(count)
        return feature

    @staticmethod
    def _fe_issuer_common_name_entropy(sample):
        feature = []
        for item in sample["Issuer_Common_Name"]:
            p, lns = Counter(item), float(len(item))
            ent = -sum(count / lns * math.log(count / lns, 2) for count in list(p.values()))
            feature.append(ent)
        return feature

    def _fe_issuer_common_name_gib(self, sample):
        feature = []
        gib_model_mat = self._gib_model["mat"]
        for item in sample["Issuer_Common_Name"]:
            feature.append(avg_transition_prob(item, gib_model_mat))
        return feature

    @staticmethod
    def _fe_issuer_country_value(sample):
        return pd.get_dummies(sample["Issuer_Country"])

    @staticmethod
    def _fe_issuer_state_province_value(sample):
        return pd.get_dummies(sample["Issuer_State_Province"])

    @staticmethod
    def _fe_issuer_organization_value(sample):
        return pd.get_dummies(sample["Issuer_Organization"])

    @staticmethod
    def _fe_issuer_organizational_unit_value(sample):
        return pd.get_dummies(sample["Issuer_Organizational_Unit"])

    @staticmethod
    def _fe_issuer_common_name_value(sample):
        return pd.get_dummies(sample["Issuer_Common_Name"])

    @staticmethod
    def _fe_issuer_location_value(sample):
        return pd.get_dummies(sample["Issuer_Location"])

    @staticmethod
    def _fe_issuer_email_address_value(sample):
        return pd.get_dummies(sample["Issuer_Email_Address"])

    @staticmethod
    def _fe_has_issuer_country(sample):
        feature = []
        for item in sample["Issuer_Country"]:
            if not item:
                feature.append(0)
            else:
                feature.append(1)
        return feature

    @staticmethod
    def _fe_has_issuer_state_province(sample):
        feature = []
        for item in sample["Issuer_State_Province"]:
            if not item:
                feature.append(0)
            else:
                feature.append(1)
        return feature

    @staticmethod
    def _fe_has_issuer_organization(sample):
        feature = []
        for item in sample["Issuer_Organization"]:
            if not item:
                feature.append(0)
            else:
                feature.append(1)
        return feature

    @staticmethod
    def _fe_has_issuer_organizational_unit(sample):
        feature = []
        for item in sample["Issuer_Organizational_Unit"]:
            if not item:
                feature.append(0)
            else:
                feature.append(1)
        return feature

    @staticmethod
    def _fe_has_issuer_common_name(sample):
        feature = []
        for item in sample["Issuer_Common_Name"]:
            if not item:
                feature.append(0)
            else:
                feature.append(1)
        return feature

    @staticmethod
    def _fe_has_issuer_location(sample):
        feature = []
        for item in sample["Issuer_Location"]:
            if not item:
                feature.append(0)
            else:
                feature.append(1)
        return feature

    @staticmethod
    def _fe_has_issuer_email_address(sample):
        feature = []
        for item in sample["Issuer_Email_Address"]:
            if not item:
                feature.append(0)
            else:
                feature.append(1)
        return feature

    def _fe_has_tld_in_issuer_common_name(self, sample):
        feature = []
        for item in sample["Issuer_Common_Name"]:
            if not item:
                feature.append(-1)
            else:
                flag = False
                for tld in self._tlds:
                    fqdn_parts = self._fqdn_parts(item)
                    if fqdn_parts["tld"] == tld:
                        feature.append(1)
                        flag = True
                        break
                if not flag:
                    feature.append(0)
        return feature

    def _fe_has_suspicious_tld_in_issuer_cn(self, sample):
        feature = []
        for item in sample["Issuer_Common_Name"]:
            if not item:
                feature.append(-1)
            else:
                flag = False
                for tld in self._suspicious_tlds:
                    fqdn_parts = self._fqdn_parts(item)
                    if fqdn_parts["tld"] == tld:
                        feature.append(1)
                        flag = True
                        break
                if not flag:
                    feature.append(0)
        return feature

    def _fe_has_suspicious_kws_in_issuer_cn(self, sample):
        feature = []
        for item in sample["Issuer_Common_Name"]:
            if not item:
                feature.append(-1)
            else:
                flag = False
                for keyword in self._suspicious_keywords:
                    if keyword in item:
                        feature.append(1)
                        flag = True
                        break
                if not flag:
                    feature.append(0)
        return feature

    def _fe_has_misc_kws_in_issuer_cn(self, sample):
        feature = []
        for item in sample["Issuer_Common_Name"]:
            if not item:
                feature.append(-1)
            else:
                flag = False
                for keyword in self._misc_keywords:
                    if keyword in item:
                        feature.append(1)
                        flag = True
                        break
                if not flag:
                    feature.append(0)
        return feature

    def _fe_suspicious_kws_similarity_in_issuer_cn(self, sample):
        feature = []
        for item in sample["Issuer_Common_Name"]:
            if not item:
                feature.append(-1)
            else:
                words = re.split("\W+", item)
                min_dist = 999
                for keyword in self._suspicious_keywords:
                    for word in words:
                        dist = distance(word, keyword)
                        min_dist = min(min_dist, dist)
                feature.append(min_dist)
        return feature

    def _fe_is_issuer_common_name_ip(self, sample):
        feature = []
        for item in sample["Issuer_Common_Name"]:
            if not item:
                feature.append(-1)
            elif self._is_ip(item):
                feature.append(1)
            else:
                feature.append(0)
        return feature

    @staticmethod
    def _fe_is_issuer_only_common_name(sample):
        feature = []
        for i, row in sample.iterrows():
            if (row["Issuer_Common_Name"] and not row["Issuer_Country"] and not row["Issuer_State_Province"]
                    and not row["Issuer_Organization"] and not row["Issuer_Organizational_Unit"]
                    and not row["Issuer_Location"] and not row["Issuer_Email_Address"]):
                feature.append(1)
            else:
                feature.append(0)
        return feature

    def _fe_is_free(self, sample):
        feature = []
        chars = list(string.ascii_lowercase) + list(string.digits)
        for item in sample["Issuer_Organization"]:
            if not item:
                feature.append(-1)
            else:
                flag = False
                filter_item = "".join(char for char in item.lower() if char in chars)
                for i, issuer in enumerate(self._free_issuers):
                    filter_issuer = "".join(char for char in issuer.lower() if char in chars)
                    if self._is_same_strings(filter_item, filter_issuer, 5):
                        feature.append(1)
                        flag = True
                        break
                if not flag:
                    feature.append(0)
        return feature

    @staticmethod
    def _fe_issuer_length(sample):
        feature = []
        for i, row in sample.iterrows():
            length = 0
            length += len(row["Issuer_Country"])
            length += len(row["Issuer_State_Province"])
            length += len(row["Issuer_Organization"])
            length += len(row["Issuer_Organizational_Unit"])
            length += len(row["Issuer_Common_Name"])
            length += len(row["Issuer_Location"])
            length += len(row["Issuer_Email_Address"])
            feature.append(length)
        return feature

    """Subject"""

    @staticmethod
    def _fe_subject_count(sample):
        feature = []
        for i, row in sample.iterrows():
            count = 0
            if len(row["Subject_Country"]) > 0:
                count += 1
            if len(row["Subject_State_Province"]) > 0:
                count += 1
            if len(row["Subject_Organization"]) > 0:
                count += 1
            if len(row["Subject_Organizational_Unit"]) > 0:
                count += 1
            if len(row["Subject_Common_Name"]) > 0:
                count += 1
            if len(row["Subject_Country"]) > 0:
                count += 1
            if len(row["Subject_Email_Address"]) > 0:
                count += 1
            feature.append(count)
        return feature

    @staticmethod
    def _fe_subject_common_name_entropy(sample):
        feature = []
        for item in sample["Subject_Common_Name"]:
            p, lns = Counter(item), float(len(item))
            ent = -sum(count / lns * math.log(count / lns, 2) for count in list(p.values()))
            feature.append(ent)
        return feature

    def _fe_subject_common_name_gib(self, sample):
        feature = []
        gib_model_mat = self._gib_model["mat"]
        for item in sample["Subject_Common_Name"]:
            feature.append(avg_transition_prob(item, gib_model_mat))
        return feature

    @staticmethod
    def _fe_subject_country_value(sample):
        return pd.get_dummies(sample["Subject_Country"])

    @staticmethod
    def _fe_subject_state_province_value(sample):
        return pd.get_dummies(sample["Subject_State_Province"])

    @staticmethod
    def _fe_has_subject_country(sample):
        feature = []
        for item in sample["Subject_Country"]:
            if not item:
                feature.append(0)
            else:
                feature.append(1)
        return feature

    @staticmethod
    def _fe_has_subject_state_province(sample):
        feature = []
        for item in sample["Subject_State_Province"]:
            if not item:
                feature.append(0)
            else:
                feature.append(1)
        return feature

    @staticmethod
    def _fe_has_subject_organization(sample):
        feature = []
        for item in sample["Subject_Organization"]:
            if not item:
                feature.append(0)
            else:
                feature.append(1)
        return feature

    @staticmethod
    def _fe_has_subject_organizational_unit(sample):
        feature = []
        for item in sample["Subject_Organizational_Unit"]:
            if not item:
                feature.append(0)
            else:
                feature.append(1)
        return feature

    @staticmethod
    def _fe_has_subject_common_name(sample):
        feature = []
        for item in sample["Subject_Common_Name"]:
            if not item:
                feature.append(0)
            else:
                feature.append(1)
        return feature

    @staticmethod
    def _fe_has_subject_location(sample):
        feature = []
        for item in sample["Subject_Location"]:
            if not item:
                feature.append(0)
            else:
                feature.append(1)
        return feature

    @staticmethod
    def _fe_has_subject_email_address(sample):
        feature = []
        for item in sample["Subject_Email_Address"]:
            if not item:
                feature.append(0)
            else:
                feature.append(1)
        return feature

    def _fe_has_tld_in_subject_common_name(self, sample):
        feature = []
        for item in sample["Subject_Common_Name"]:
            if not item:
                feature.append(-1)
            else:
                flag = False
                for tld in self._tlds:
                    fqdn_parts = self._fqdn_parts(item)
                    if fqdn_parts["tld"] == tld:
                        feature.append(1)
                        flag = True
                        break
                if not flag:
                    feature.append(0)
        return feature

    def _fe_has_suspicious_tld_in_subject_cn(self, sample):
        feature = []
        for item in sample["Subject_Common_Name"]:
            if not item:
                feature.append(-1)
            else:
                flag = False
                for tld in self._suspicious_tlds:
                    fqdn_parts = self._fqdn_parts(item)
                    if fqdn_parts["tld"] == tld:
                        feature.append(1)
                        flag = True
                        break
                if not flag:
                    feature.append(0)
        return feature

    def _fe_has_suspicious_kws_in_subject_cn(self, sample):
        feature = []
        for item in sample["Subject_Common_Name"]:
            if not item:
                feature.append(-1)
            else:
                flag = False
                for keyword in self._suspicious_keywords:
                    if keyword in item:
                        feature.append(1)
                        flag = True
                        break
                if not flag:
                    feature.append(0)
        return feature

    def _fe_has_misc_kws_in_subject_cn(self, sample):
        feature = []
        for item in sample["Subject_Common_Name"]:
            if not item:
                feature.append(-1)
            else:
                flag = False
                for keyword in self._misc_keywords:
                    if keyword in item:
                        feature.append(1)
                        flag = True
                        break
                if not flag:
                    feature.append(0)
        return feature

    def _fe_suspicious_kws_similarity_in_subject_cn(self, sample):
        feature = []
        for item in sample["Subject_Common_Name"]:
            if not item:
                feature.append(-1)
            else:
                words = re.split("\W+", item)
                min_dist = 999
                for keyword in self._suspicious_keywords:
                    for word in words:
                        dist = distance(word, keyword)
                        min_dist = min(min_dist, dist)
                feature.append(min_dist)
        return feature

    def _fe_is_subject_common_name_ip(self, sample):
        feature = []
        for item in sample["Subject_Common_Name"]:
            if not item:
                feature.append(-1)
            elif self._is_ip(item):
                feature.append(1)
            else:
                feature.append(0)
        return feature

    @staticmethod
    def _fe_is_subject_only_common_name(sample):
        feature = []
        for i, row in sample.iterrows():
            if (row["Subject_Common_Name"] and not row["Subject_Country"] and not row["Subject_State_Province"]
                    and not row["Subject_Organization"] and not row["Subject_Organizational_Unit"]
                    and not row["Subject_Location"] and not row["Subject_Email_Address"]):
                feature.append(1)
            else:
                feature.append(0)
        return feature

    @staticmethod
    def _fe_subject_length(sample):
        feature = []
        for i, row in sample.iterrows():
            length = 0
            length += len(row["Subject_Country"])
            length += len(row["Subject_State_Province"])
            length += len(row["Subject_Organization"])
            length += len(row["Subject_Organizational_Unit"])
            length += len(row["Subject_Common_Name"])
            length += len(row["Subject_Location"])
            length += len(row["Subject_Email_Address"])
            feature.append(length)
        return feature

    """Validity"""

    @staticmethod
    def _fe_is_expired(sample):
        feature = []
        for item in sample["Is_Expired"]:
            if item is True or item == "TRUE" or item == "True" or item == "true":
                feature.append(1)
            elif item is False or item == "FALSE" or item == "False" or item == "false":
                feature.append(0)
            else:
                feature.append(-1)
        return feature

    """Extension"""

    @staticmethod
    def _fe_ca(sample):
        feature = []
        for item in sample["Extension_CA"]:
            if item is True or item == "TRUE" or item == "True" or item == "true":
                feature.append(1)
            elif item is False or item == "FALSE" or item == "False" or item == "false":
                feature.append(0)
            else:
                feature.append(-1)
        return feature

    @staticmethod
    def _fe_subject_alt_names_count(sample):
        feature = []
        for item in sample["Extension_Subject_Alt_Names"]:
            if not item:
                feature.append(0)
            else:
                subject_alt_names = ast.literal_eval(item)
                feature.append(len(subject_alt_names))
        return feature

    @staticmethod
    def _fe_ocsp_no_check_critical(sample):
        regular = "critical=(.*?), "
        ocsp_no_check_critical = sample["OCSPNoCheck"].str.extract(regular)
        ocsp_no_check_critical.columns = ["OCSP_No_Check_Critical"]
        ocsp_no_check_critical = ocsp_no_check_critical.replace({"False": 0, "True": 1})
        ocsp_no_check_critical = ocsp_no_check_critical.fillna(-1)
        return ocsp_no_check_critical

    @staticmethod
    def _fe_tls_feature_critical(sample):
        regular = "critical=(.*?), "
        tls_feature_critical = sample["TLSFeature"].str.extract(regular)
        tls_feature_critical.columns = ["TLS_Feature_Critical"]
        tls_feature_critical = tls_feature_critical.replace({"False": 0, "True": 1})
        tls_feature_critical = tls_feature_critical.fillna(-1)
        return tls_feature_critical

    @staticmethod
    def _fe_tls_feature_features(sample):
        regular = "features=\[(.*?)\]"
        tls_feature_features = sample["TLSFeature"].str.extract(regular)
        tls_feature_features.columns = ["TLS_Feature_Features"]
        tls_feature_features["TLS_Feature_Features"] = [1 if pd.notnull(item) else 0
                                                        for item in tls_feature_features["TLS_Feature_Features"]]
        return tls_feature_features

    @staticmethod
    def _fe_unknown_oid_critical(sample):
        regular = "critical=(.*?), "
        unknown_oid_critical = sample["Unknown OID"].str.extract(regular)
        unknown_oid_critical.columns = ["Unknown_OID_Critical"]
        unknown_oid_critical = unknown_oid_critical.replace({"False": 0, "True": 1})
        unknown_oid_critical = unknown_oid_critical.fillna(-1)
        return unknown_oid_critical

    @staticmethod
    def _fe_unknown_oid_oid(sample):
        regular = "<ObjectIdentifier\(oid=(.*?), "
        unknown_oid_oid = sample["Unknown OID"].str.extract(regular)
        unknown_oid_oid.columns = ["Unknown_OID_OID"]
        unknown_oid_oid = unknown_oid_oid.fillna("")
        return pd.get_dummies(unknown_oid_oid["Unknown_OID_OID"])

    @staticmethod
    def _fe_unknown_oid_value(sample):
        regular = "\)>, value=(.*?)\)>\)>"
        unknown_oid_value = sample["Unknown OID"].str.extract(regular)
        unknown_oid_value.columns = ["Unknown_OID_Value"]
        unknown_oid_value = unknown_oid_value.fillna("")
        return pd.get_dummies(unknown_oid_value["Unknown_OID_Value"])

    @staticmethod
    def _fe_authority_info_access_critical(sample):
        regular = "critical=(.*?), "
        authority_info_access_critical = sample["authorityInfoAccess"].str.extract(regular)
        authority_info_access_critical.columns = ["Authority_Info_Access_Critical"]
        authority_info_access_critical = authority_info_access_critical.replace({"False": 0, "True": 1})
        authority_info_access_critical = authority_info_access_critical.fillna(-1)
        return authority_info_access_critical

    @staticmethod
    def _fe_authority_info_access_ocsp(sample):
        regular = "name=OCSP\)>, access_location=<UniformResourceIdentifier\(value=\'(.*?)\'\)>\)>"
        value = sample["authorityInfoAccess"].str.findall(regular)
        authority_info_access_ocsp = pd.DataFrame({"Authority_Info_Access_OCSP": value})
        authority_info_access_ocsp["Authority_Info_Access_OCSP"] = [
            ",".join(sorted(item)) if len(item) > 0 else ""
            for item in authority_info_access_ocsp["Authority_Info_Access_OCSP"]
        ]
        return pd.get_dummies(authority_info_access_ocsp["Authority_Info_Access_OCSP"])

    @staticmethod
    def _fe_authority_info_access_ca_issuers(sample):
        regular = "name=caIssuers\)>, access_location=<UniformResourceIdentifier\(value=\'(.*?)\'\)>\)>"
        value = sample["authorityInfoAccess"].str.findall(regular)
        authority_info_access_ca_issuers = pd.DataFrame({"Authority_Info_Access_CA_Issuers": value})
        authority_info_access_ca_issuers["Authority_Info_Access_CA_Issuers"] = [
            ",".join(sorted(item)) if len(item) > 0 else ""
            for item in authority_info_access_ca_issuers["Authority_Info_Access_CA_Issuers"]
        ]
        return pd.get_dummies(authority_info_access_ca_issuers["Authority_Info_Access_CA_Issuers"])

    @staticmethod
    def _fe_authority_key_identifier_critical(sample):
        regular = "critical=(.*?), "
        authority_key_identifier_critical = sample["authorityKeyIdentifier"].str.extract(regular)
        authority_key_identifier_critical.columns = ["Authority_Key_Identifier_Critical"]
        authority_key_identifier_critical = authority_key_identifier_critical.replace({"False": 0, "True": 1})
        authority_key_identifier_critical = authority_key_identifier_critical.fillna(-1)
        return authority_key_identifier_critical

    @staticmethod
    def _fe_authority_key_identifier_key_identifier(sample):
        regular = "key_identifier=(.*?), "
        authority_key_identifier_key_identifier = sample["authorityKeyIdentifier"].str.extract(regular)
        authority_key_identifier_key_identifier.columns = ["Authority_Key_Identifier_Key_Identifier"]
        authority_key_identifier_key_identifier = authority_key_identifier_key_identifier.fillna("")
        return pd.get_dummies(authority_key_identifier_key_identifier["Authority_Key_Identifier_Key_Identifier"])

    @staticmethod
    def _fe_authority_key_identifier_authority_cert_issuer(sample):
        regular = "authority_cert_issuer=(.*?), "
        authority_key_identifier_authority_cert_issuer = sample["authorityKeyIdentifier"].str.extract(regular)
        authority_key_identifier_authority_cert_issuer.columns = ["Authority_Key_Identifier_Authority_Cert_Issuer"]
        authority_key_identifier_authority_cert_issuer = authority_key_identifier_authority_cert_issuer.fillna("")
        return pd.get_dummies(
            authority_key_identifier_authority_cert_issuer["Authority_Key_Identifier_Authority_Cert_Issuer"])

    @staticmethod
    def _fe_authority_key_identifier_authority_cert_serial_number(sample):
        regular = "authority_cert_serial_number=(.*?)\)>"
        authority_key_identifier_authority_cert_serial_number = sample["authorityKeyIdentifier"].str.extract(regular)
        authority_key_identifier_authority_cert_serial_number.columns = [
            "Authority_Key_Identifier_Authority_Cert_Serial_Number"]
        authority_key_identifier_authority_cert_serial_number = authority_key_identifier_authority_cert_serial_number.fillna("")
        return pd.get_dummies(authority_key_identifier_authority_cert_serial_number[
                                  "Authority_Key_Identifier_Authority_Cert_Serial_Number"])

    @staticmethod
    def _fe_basic_constraints_critical(sample):
        regular = "critical=(.*?), "
        basic_constraints_critical = sample["basicConstraints"].str.extract(regular)
        basic_constraints_critical.columns = ["Basic_Constraints_Critical"]
        basic_constraints_critical = basic_constraints_critical.replace({"False": 0, "True": 1})
        basic_constraints_critical = basic_constraints_critical.fillna(-1)
        return basic_constraints_critical

    @staticmethod
    def _fe_basic_constraints_ca(sample):
        regular = "ca=(.*?), "
        basic_constraints_ca = sample["basicConstraints"].str.extract(regular)
        basic_constraints_ca.columns = ["Basic_Constraints_CA"]
        basic_constraints_ca = basic_constraints_ca.replace({"False": 0, "True": 1})
        basic_constraints_ca = basic_constraints_ca.fillna(-1)
        return basic_constraints_ca

    @staticmethod
    def _fe_basic_constraints_path_length(sample):
        regular = "path_length=(.*?)\)>\)>"
        basic_constraints_path_length = sample["basicConstraints"].str.extract(regular)
        basic_constraints_path_length.columns = ["Basic_Constraints_Path_Length"]
        basic_constraints_path_length = basic_constraints_path_length.fillna("")
        return pd.get_dummies(basic_constraints_path_length["Basic_Constraints_Path_Length"])

    @staticmethod
    def _fe_crl_distribution_points_critical(sample):
        regular = "critical=(.*?), "
        crl_distribution_points_critical = sample["cRLDistributionPoints"].str.extract(regular)
        crl_distribution_points_critical.columns = ["CRL_Distribution_Points_Critical"]
        crl_distribution_points_critical = crl_distribution_points_critical.replace({"False": 0, "True": 1})
        crl_distribution_points_critical = crl_distribution_points_critical.fillna(-1)
        return crl_distribution_points_critical

    @staticmethod
    def _fe_crl_distribution_points_value(sample):
        regular = "<CRLDistributionPoints\(\[(.*?)\)>\]\)>\)>"
        crl_distribution_points_value = sample["cRLDistributionPoints"].str.extract(regular)
        crl_distribution_points_value.columns = ["CRL_Distribution_Points_Value"]
        crl_distribution_points_value["CRL_Distribution_Points_Value"] = [
            [element[len("<DistributionPoint("):] if "<DistributionPoint(" in element else element
             for element in item.split(")>, <DistributionPoint(")]
            if pd.notnull(item) else [] for item in crl_distribution_points_value["CRL_Distribution_Points_Value"]
        ]
        regular_full_name = "full_name=\[(.*?)\], "
        value = []
        for item in crl_distribution_points_value["CRL_Distribution_Points_Value"]:
            if len(item) > 0:
                extracted_item = []
                for element in item:
                    full_name = re.search(regular_full_name, element).group(1)
                    extracted_item.append(full_name)
                value.append(",".join(sorted(extracted_item)))
            else:
                value.append("")
        crl_distribution_points_value = pd.DataFrame({"CRL_Distribution_Points_Value": value})
        return pd.get_dummies(crl_distribution_points_value["CRL_Distribution_Points_Value"])

    @staticmethod
    def _fe_certificate_policies_critical(sample):
        regular = "critical=(.*?), "
        certificate_policies_critical = sample["certificatePolicies"].str.extract(regular)
        certificate_policies_critical.columns = ["Certificate_Policies_Critical"]
        certificate_policies_critical = certificate_policies_critical.replace({"False": 0, "True": 1})
        certificate_policies_critical = certificate_policies_critical.fillna(-1)
        return certificate_policies_critical

    @staticmethod
    def _fe_certificate_policies_value(extensions):
        regular = "<CertificatePolicies\(\[(.*?)\)>\]\)>\)>"
        certificate_policies_value = extensions["certificatePolicies"].str.extract(regular)
        certificate_policies_value.columns = ["Certificate_Policies_Value"]
        certificate_policies_value["Certificate_Policies_Value"] = [
            [element[len("<PolicyInformation("):] if "<PolicyInformation(" in element else element
             for element in item.split(")>, <PolicyInformation(")]
            if pd.notnull(item) else [] for item in certificate_policies_value["Certificate_Policies_Value"]
        ]
        value = []
        for index, row in certificate_policies_value.iterrows():
            item = row[0]
            if len(item) > 0:
                value.append(len(item))
            else:
                value.append(0)
        return pd.DataFrame({"Certificate_Policies_Value": value})

    @staticmethod
    def _fe_extended_key_usage_critical(sample):
        regular = "critical=(.*?), "
        extended_key_usage_critical = sample["extendedKeyUsage"].str.extract(regular)
        extended_key_usage_critical.columns = ["Extended_Key_Usage_Critical"]
        extended_key_usage_critical = extended_key_usage_critical.replace({"False": 0, "True": 1})
        extended_key_usage_critical = extended_key_usage_critical.fillna(-1)
        return extended_key_usage_critical

    # Extended_Key_Usage_Value: one-hot encoding is the best choice now

    @staticmethod
    def _fe_extended_key_usage_server_auth(sample):
        regular = "<ExtendedKeyUsage\(\[(.*?)\)>\]\)>\)>"
        extended_key_usage_server_auth = sample["extendedKeyUsage"].str.extract(regular)
        extended_key_usage_server_auth.columns = ["Extended_Key_Usage_Server_Auth"]
        extended_key_usage_server_auth["Extended_Key_Usage_Server_Auth"] = [
            [element[len("<ObjectIdentifier("):] if "<ObjectIdentifier(" in element else element
             for element in item.split(")>, <ObjectIdentifier(")]
            if pd.notnull(item) else [] for item in extended_key_usage_server_auth["Extended_Key_Usage_Server_Auth"]
        ]
        regular_name = "name=(.*?)$"
        value = []
        for item in extended_key_usage_server_auth["Extended_Key_Usage_Server_Auth"]:
            if len(item) > 0:
                flag = False
                for element in item:
                    name = re.search(regular_name, element).group(1)
                    if name == "serverAuth":
                        flag = True
                        break
                if flag is True:
                    value.append(1)
                else:
                    value.append(0)
            else:
                value.append(-1)
        return pd.DataFrame({"Extended_Key_Usage_Server_Auth": value})

    @staticmethod
    def _fe_extended_key_usage_client_auth(sample):
        regular = "<ExtendedKeyUsage\(\[(.*?)\)>\]\)>\)>"
        extended_key_usage_client_auth = sample["extendedKeyUsage"].str.extract(regular)
        extended_key_usage_client_auth.columns = ["Extended_Key_Usage_Client_Auth"]
        extended_key_usage_client_auth["Extended_Key_Usage_Client_Auth"] = [
            [element[len("<ObjectIdentifier("):] if "<ObjectIdentifier(" in element else element
             for element in item.split(")>, <ObjectIdentifier(")]
            if pd.notnull(item) else [] for item in extended_key_usage_client_auth["Extended_Key_Usage_Client_Auth"]
        ]
        regular_name = "name=(.*?)$"
        value = []
        for item in extended_key_usage_client_auth["Extended_Key_Usage_Client_Auth"]:
            if len(item) > 0:
                flag = False
                for element in item:
                    name = re.search(regular_name, element).group(1)
                    if name == "clientAuth":
                        flag = True
                        break
                if flag is True:
                    value.append(1)
                else:
                    value.append(0)
            else:
                value.append(-1)
        return pd.DataFrame({"Extended_Key_Usage_Client_Auth": value})

    @staticmethod
    def _fe_extended_key_usage_unknown_oid(sample):
        regular = "<ExtendedKeyUsage\(\[(.*?)\)>\]\)>\)>"
        extended_key_usage_unknown_oid = sample["extendedKeyUsage"].str.extract(regular)
        extended_key_usage_unknown_oid.columns = ["Extended_Key_Usage_Unknown_OID"]
        extended_key_usage_unknown_oid["Extended_Key_Usage_Unknown_OID"] = [
            [element[len("<ObjectIdentifier("):] if "<ObjectIdentifier(" in element else element
             for element in item.split(")>, <ObjectIdentifier(")]
            if pd.notnull(item) else [] for item in extended_key_usage_unknown_oid["Extended_Key_Usage_Unknown_OID"]
        ]
        regular_name = "name=(.*?)$"
        value = []
        for item in extended_key_usage_unknown_oid["Extended_Key_Usage_Unknown_OID"]:
            if len(item) > 0:
                flag = False
                for element in item:
                    name = re.search(regular_name, element).group(1)
                    if name == "Unknown OID":
                        flag = True
                        break
                if flag is True:
                    value.append(1)
                else:
                    value.append(0)
            else:
                value.append(-1)
        return pd.DataFrame({"Extended_Key_Usage_Unknown_OID": value})

    @staticmethod
    def _fe_extended_key_usage_ocsp_signing(sample):
        regular = "<ExtendedKeyUsage\(\[(.*?)\)>\]\)>\)>"
        extended_key_usage_ocsp_signing = sample["extendedKeyUsage"].str.extract(regular)
        extended_key_usage_ocsp_signing.columns = ["Extended_Key_Usage_OCSP_Signing"]
        extended_key_usage_ocsp_signing["Extended_Key_Usage_OCSP_Signing"] = [
            [element[len("<ObjectIdentifier("):] if "<ObjectIdentifier(" in element else element
             for element in item.split(")>, <ObjectIdentifier(")]
            if pd.notnull(item) else [] for item in extended_key_usage_ocsp_signing["Extended_Key_Usage_OCSP_Signing"]
        ]
        regular_name = "name=(.*?)$"
        value = []
        for item in extended_key_usage_ocsp_signing["Extended_Key_Usage_OCSP_Signing"]:
            if len(item) > 0:
                flag = False
                for element in item:
                    name = re.search(regular_name, element).group(1)
                    if name == "OCSPSigning":
                        flag = True
                        break
                if flag is True:
                    value.append(1)
                else:
                    value.append(0)
            else:
                value.append(-1)
        return pd.DataFrame({"Extended_Key_Usage_OCSP_Signing": value})

    @staticmethod
    def _fe_extended_key_usage_code_signing(sample):
        regular = "<ExtendedKeyUsage\(\[(.*?)\)>\]\)>\)>"
        extended_key_usage_code_signing = sample["extendedKeyUsage"].str.extract(regular)
        extended_key_usage_code_signing.columns = ["Extended_Key_Usage_Code_Signing"]
        extended_key_usage_code_signing["Extended_Key_Usage_Code_Signing"] = [
            [element[len("<ObjectIdentifier("):] if "<ObjectIdentifier(" in element else element
             for element in item.split(")>, <ObjectIdentifier(")]
            if pd.notnull(item) else [] for item in extended_key_usage_code_signing["Extended_Key_Usage_Code_Signing"]
        ]
        regular_name = "name=(.*?)$"
        value = []
        for item in extended_key_usage_code_signing["Extended_Key_Usage_Code_Signing"]:
            if len(item) > 0:
                flag = False
                for element in item:
                    name = re.search(regular_name, element).group(1)
                    if name == "codeSigning":
                        flag = True
                        break
                if flag is True:
                    value.append(1)
                else:
                    value.append(0)
            else:
                value.append(-1)
        return pd.DataFrame({"Extended_Key_Usage_Code_Signing": value})

    @staticmethod
    def _fe_extended_key_usage_email_protection(sample):
        regular = "<ExtendedKeyUsage\(\[(.*?)\)>\]\)>\)>"
        extended_key_usage_email_protection = sample["extendedKeyUsage"].str.extract(regular)
        extended_key_usage_email_protection.columns = ["Extended_Key_Usage_Email_Protection"]
        extended_key_usage_email_protection["Extended_Key_Usage_Email_Protection"] = [
            [element[len("<ObjectIdentifier("):] if "<ObjectIdentifier(" in element else element
             for element in item.split(")>, <ObjectIdentifier(")]
            if pd.notnull(item) else []
            for item in extended_key_usage_email_protection["Extended_Key_Usage_Email_Protection"]
        ]
        regular_name = "name=(.*?)$"
        value = []
        for item in extended_key_usage_email_protection["Extended_Key_Usage_Email_Protection"]:
            if len(item) > 0:
                flag = False
                for element in item:
                    name = re.search(regular_name, element).group(1)
                    if name == "emailProtection":
                        flag = True
                        break
                if flag is True:
                    value.append(1)
                else:
                    value.append(0)
            else:
                value.append(-1)
        return pd.DataFrame({"Extended_Key_Usage_Email_Protection": value})

    @staticmethod
    def _fe_extended_key_usage_time_stamping(sample):
        regular = "<ExtendedKeyUsage\(\[(.*?)\)>\]\)>\)>"
        extended_key_usage_time_stamping = sample["extendedKeyUsage"].str.extract(regular)
        extended_key_usage_time_stamping.columns = ["Extended_Key_Usage_Time_Stamping"]
        extended_key_usage_time_stamping["Extended_Key_Usage_Time_Stamping"] = [
            [element[len("<ObjectIdentifier("):] if "<ObjectIdentifier(" in element else element
             for element in item.split(")>, <ObjectIdentifier(")]
            if pd.notnull(item) else [] for item in extended_key_usage_time_stamping["Extended_Key_Usage_Time_Stamping"]
        ]
        regular_name = "name=(.*?)$"
        value = []
        for item in extended_key_usage_time_stamping["Extended_Key_Usage_Time_Stamping"]:
            if len(item) > 0:
                flag = False
                for element in item:
                    name = re.search(regular_name, element).group(1)
                    if name == "timeStamping":
                        flag = True
                        break
                if flag is True:
                    value.append(1)
                else:
                    value.append(0)
            else:
                value.append(-1)
        return pd.DataFrame({"Extended_Key_Usage_Time_Stamping": value})

    @staticmethod
    def _fe_freshest_crl_critical(sample):
        regular = "critical=(.*?), "
        freshest_crl_critical = sample["freshestCRL"].str.extract(regular)
        freshest_crl_critical.columns = ["Freshest_CRL_Critical"]
        freshest_crl_critical = freshest_crl_critical.replace({"False": 0, "True": 1})
        freshest_crl_critical = freshest_crl_critical.fillna(-1)
        return freshest_crl_critical

    @staticmethod
    def _fe_freshest_crl_value(sample):
        regular = "<FreshestCRL\(\[(.*?)\)>\]\)>\)>"
        freshest_crl_value = sample["freshestCRL"].str.extract(regular)
        freshest_crl_value.columns = ["Freshest_CRL_Value"]
        freshest_crl_value["Freshest_CRL_Value"] = [
            [element[len("<DistributionPoint("):] if "<DistributionPoint(" in element else element
             for element in item.split(")>, <DistributionPoint(")]
            if pd.notnull(item) else [] for item in freshest_crl_value["Freshest_CRL_Value"]
        ]
        regular_full_name = "full_name=\[(.*?)\], "
        value = []
        for item in freshest_crl_value["Freshest_CRL_Value"]:
            if len(item) > 0:
                extracted_item = []
                for element in item:
                    full_name = re.search(regular_full_name, element).group(1).split(", ")
                    for name in full_name:
                        extracted_item.append(name)
                value.append(",".join(sorted(extracted_item)))
            else:
                value.append("")
        freshest_crl_value = pd.DataFrame({"Freshest_CRL_Value": value})
        return pd.get_dummies(freshest_crl_value["Freshest_CRL_Value"])

    @staticmethod
    def _fe_issuer_alt_name_critical(sample):
        regular = "critical=(.*?), "
        issuer_alt_name_critical = sample["issuerAltName"].str.extract(regular)
        issuer_alt_name_critical.columns = ["Issuer_Alt_Name_Critical"]
        issuer_alt_name_critical = issuer_alt_name_critical.replace({"False": 0, "True": 1})
        issuer_alt_name_critical = issuer_alt_name_critical.fillna(-1)
        return issuer_alt_name_critical

    @staticmethod
    def _fe_issuer_alt_name_value(sample):
        regular = "<GeneralNames\(\[(.*?)\]\)>\)>"
        issuer_alt_name_value = sample["issuerAltName"].str.extract(regular)
        issuer_alt_name_value.columns = ["Issuer_Alt_Name_Value"]
        issuer_alt_name_value["Issuer_Alt_Name_Value"] = [
            ["" if element == "" else "<" + element + ")>"
            if not element.startswith("<") and not element.endswith(")>") else "<" + element
            if not element.startswith("<") else element + ")>"
            if not element.endswith(")>") else element
             for element in item.split(")>, <")]
            if pd.notnull(item) else [] for item in issuer_alt_name_value["Issuer_Alt_Name_Value"]
        ]
        issuer_alt_name_value["Issuer_Alt_Name_Value"] = [
            ",".join(sorted(item)) if len(item) > 0 else ""
            for item in issuer_alt_name_value["Issuer_Alt_Name_Value"]
        ]
        return pd.get_dummies(issuer_alt_name_value["Issuer_Alt_Name_Value"])

    @staticmethod
    def _fe_key_usage_critical(sample):
        regular = "critical=(.*?), "
        key_usage_critical = sample["keyUsage"].str.extract(regular)
        key_usage_critical.columns = ["Key_Usage_Critical"]
        key_usage_critical = key_usage_critical.replace({"False": 0, "True": 1})
        key_usage_critical = key_usage_critical.fillna(-1)
        return key_usage_critical

    @staticmethod
    def _fe_key_usage_digital_signature(sample):
        regular = "digital_signature=(.*?), "
        key_usage_digital_signature = sample["keyUsage"].str.extract(regular)
        key_usage_digital_signature.columns = ["Key_Usage_Digital_Signature"]
        key_usage_digital_signature = key_usage_digital_signature.replace({"False": 0, "True": 1})
        key_usage_digital_signature = key_usage_digital_signature.fillna(-1)
        return key_usage_digital_signature

    @staticmethod
    def _fe_key_usage_content_commitment(sample):
        regular = "content_commitment=(.*?), "
        key_usage_content_commitment = sample["keyUsage"].str.extract(regular)
        key_usage_content_commitment.columns = ["Key_Usage_Content_Commitment"]
        key_usage_content_commitment = key_usage_content_commitment.replace({"False": 0, "True": 1})
        key_usage_content_commitment = key_usage_content_commitment.fillna(-1)
        return key_usage_content_commitment

    @staticmethod
    def _fe_key_usage_key_encipherment(sample):
        regular = "key_encipherment=(.*?), "
        key_usage_key_encipherment = sample["keyUsage"].str.extract(regular)
        key_usage_key_encipherment.columns = ["Key_Usage_Key_Encipherment"]
        key_usage_key_encipherment = key_usage_key_encipherment.replace({"False": 0, "True": 1})
        key_usage_key_encipherment = key_usage_key_encipherment.fillna(-1)
        return key_usage_key_encipherment

    @staticmethod
    def _fe_key_usage_data_encipherment(sample):
        regular = "data_encipherment=(.*?), "
        key_usage_data_encipherment = sample["keyUsage"].str.extract(regular)
        key_usage_data_encipherment.columns = ["Key_Usage_Data_Encipherment"]
        key_usage_data_encipherment = key_usage_data_encipherment.replace({"False": 0, "True": 1})
        key_usage_data_encipherment = key_usage_data_encipherment.fillna(-1)
        return key_usage_data_encipherment

    @staticmethod
    def _fe_key_usage_key_agreement(sample):
        regular = "key_agreement=(.*?), "
        key_usage_key_agreement = sample["keyUsage"].str.extract(regular)
        key_usage_key_agreement.columns = ["Key_Usage_Key_Agreement"]
        key_usage_key_agreement = key_usage_key_agreement.replace({"False": 0, "True": 1})
        key_usage_key_agreement = key_usage_key_agreement.fillna(-1)
        return key_usage_key_agreement

    @staticmethod
    def _fe_key_usage_key_cert_sign(sample):
        regular = "key_cert_sign=(.*?), "
        key_usage_key_cert_sign = sample["keyUsage"].str.extract(regular)
        key_usage_key_cert_sign.columns = ["Key_Usage_Key_Cert_Sign"]
        key_usage_key_cert_sign = key_usage_key_cert_sign.replace({"False": 0, "True": 1})
        key_usage_key_cert_sign = key_usage_key_cert_sign.fillna(-1)
        return key_usage_key_cert_sign

    @staticmethod
    def _fe_key_usage_crl_sign(sample):
        regular = "crl_sign=(.*?), "
        key_usage_crl_sign = sample["keyUsage"].str.extract(regular)
        key_usage_crl_sign.columns = ["Key_Usage_Crl_Sign"]
        key_usage_crl_sign = key_usage_crl_sign.replace({"False": 0, "True": 1})
        key_usage_crl_sign = key_usage_crl_sign.fillna(-1)
        return key_usage_crl_sign

    @staticmethod
    def _fe_key_usage_encipher_only(sample):
        regular = "encipher_only=(.*?), "
        key_usage_encipher_only = sample["keyUsage"].str.extract(regular)
        key_usage_encipher_only.columns = ["Key_Usage_Encipher_Only"]
        key_usage_encipher_only = key_usage_encipher_only.replace({"False": 0, "True": 1})
        key_usage_encipher_only = key_usage_encipher_only.fillna(-1)
        return key_usage_encipher_only

    @staticmethod
    def _fe_key_usage_decipher_only(sample):
        regular = "decipher_only=(.*?)\)>"
        key_usage_decipher_only = sample["keyUsage"].str.extract(regular)
        key_usage_decipher_only.columns = ["Key_Usage_Decipher_Only"]
        key_usage_decipher_only = key_usage_decipher_only.replace({"False": 0, "True": 1})
        key_usage_decipher_only = key_usage_decipher_only.fillna(-1)
        return key_usage_decipher_only

    @staticmethod
    def _fe_signed_certificate_timestamp_list_critical(sample):
        regular = "critical=(.*?), "
        signed_certificate_timestamp_list_critical = sample["signedCertificateTimestampList"].str.extract(regular)
        signed_certificate_timestamp_list_critical.columns = ["Signed_Certificate_Timestamp_List_Critical"]
        signed_certificate_timestamp_list_critical = signed_certificate_timestamp_list_critical.replace(
            {"False": 0, "True": 1})
        signed_certificate_timestamp_list_critical = signed_certificate_timestamp_list_critical.fillna(-1)
        return signed_certificate_timestamp_list_critical

    @staticmethod
    def _fe_signed_certificate_timestamp_list_value(sample):
        regular = "PrecertificateSignedCertificateTimestamps\((.*?)\)>\)>"
        signed_certificate_timestamp_list_value = sample["signedCertificateTimestampList"].str.extract(regular)
        signed_certificate_timestamp_list_value.columns = ["Signed_Certificate_Timestamp_List_Value"]
        signed_certificate_timestamp_list_value["Signed_Certificate_Timestamp_List_Value"] = [
            [element for element in item.split(", ")] if pd.notnull(item) else []
            for item in signed_certificate_timestamp_list_value["Signed_Certificate_Timestamp_List_Value"]
        ]
        signed_certificate_timestamp_list_value["Signed_Certificate_Timestamp_List_Value"] = [
            len(item) for item in signed_certificate_timestamp_list_value["Signed_Certificate_Timestamp_List_Value"]
        ]
        return signed_certificate_timestamp_list_value

    @staticmethod
    def _fe_subject_alt_name_critical(sample):
        regular = "critical=(.*?), "
        subject_alt_name_critical = sample["subjectAltName"].str.extract(regular)
        subject_alt_name_critical.columns = ["Subject_Alt_Name_Critical"]
        subject_alt_name_critical = subject_alt_name_critical.replace({"False": 0, "True": 1})
        subject_alt_name_critical = subject_alt_name_critical.fillna(-1)
        return subject_alt_name_critical

    @staticmethod
    def _fe_subject_alt_name_value(sample):
        regular = "<GeneralNames\(\[(.*?)\]\)>\)>"
        subject_alt_name_value = sample["subjectAltName"].str.extract(regular)
        subject_alt_name_value.columns = ["Subject_Alt_Name_Value"]
        subject_alt_name_value["Subject_Alt_Name_Value"] = [
            ["<" + element + ")>" if not element.startswith("<") and not element.endswith(")>") else "<" + element
            if not element.startswith("<") else element + ")>"
            if not element.endswith(")>") else element
             for element in item.split(")>, <")]
            if pd.notnull(item) else [] for item in subject_alt_name_value["Subject_Alt_Name_Value"]
        ]
        subject_alt_name_value["Subject_Alt_Name_Value"] = [
            len(item) for item in subject_alt_name_value["Subject_Alt_Name_Value"]
        ]
        return subject_alt_name_value

    @staticmethod
    def _fe_subject_directory_attributes_critical(sample):
        regular = "critical=(.*?), "
        subject_directory_attributes_critical = sample["subjectDirectoryAttributes"].str.extract(regular)
        subject_directory_attributes_critical.columns = ["Subject_Directory_Attributes_Critical"]
        subject_directory_attributes_critical = subject_directory_attributes_critical.replace({"False": 0, "True": 1})
        subject_directory_attributes_critical = subject_directory_attributes_critical.fillna(-1)
        return subject_directory_attributes_critical

    @staticmethod
    def _fe_subject_directory_attributes_value(sample):
        regular = "\)\>, value=(.*?)\)>\)>"
        subject_directory_attributes_value = sample["subjectDirectoryAttributes"].str.extract(regular)
        subject_directory_attributes_value.columns = ["Subject_Directory_Attributes_Value"]
        subject_directory_attributes_value = subject_directory_attributes_value.fillna("")
        return pd.get_dummies(subject_directory_attributes_value["Subject_Directory_Attributes_Value"])

    @staticmethod
    def _fe_subject_key_identifier_critical(sample):
        regular = "critical=(.*?), "
        subject_key_identifier_critical = sample["subjectKeyIdentifier"].str.extract(regular)
        subject_key_identifier_critical.columns = ["Subject_Key_Identifier_Critical"]
        subject_key_identifier_critical = subject_key_identifier_critical.replace({"False": 0, "True": 1})
        subject_key_identifier_critical = subject_key_identifier_critical.fillna(-1)
        return subject_key_identifier_critical

    @staticmethod
    def _fe_is_extended_validated(sample):
        cert_policies = pd.read_csv(FEATURE_PATHS["cert_policies"], keep_default_na=False, index_col=False)
        ev_oids = {}
        for i, row in cert_policies.iterrows():
            if row["tls_ev"] == "TRUE" or row["codesigning_ev"] == "TRUE":
                ev_oids[row["oid"]] = row["oid"]
        feature = []
        for i, row in sample.iterrows():
            item = row["Extension_OIDs"]
            if not item:
                feature.append(-1)
            else:
                oids = ast.literal_eval(item)
                flag = False
                for oid in oids:
                    if oid in ev_oids:
                        feature.append(1)
                        flag = True
                        break
                if not flag:
                    feature.append(0)
        return feature

    @staticmethod
    def _fe_is_organization_validated(sample):
        cert_policies = pd.read_csv(FEATURE_PATHS["cert_policies"], keep_default_na=False, index_col=False)
        ov_oids = {}
        for i, row in cert_policies.iterrows():
            if row["tls_ov"] == "TRUE" or row["codesigning_ov"] == "TRUE":
                ov_oids[row["oid"]] = row["oid"]
        feature = []
        for i, row in sample.iterrows():
            item = row["Extension_OIDs"]
            if not item:
                feature.append(-1)
            else:
                oids = ast.literal_eval(item)
                flag = False
                for oid in oids:
                    if oid in ov_oids:
                        feature.append(1)
                        flag = True
                        break
                if not flag:
                    feature.append(0)
        return feature

    @staticmethod
    def _fe_is_domain_validated(sample):
        cert_policies = pd.read_csv(FEATURE_PATHS["cert_policies"], keep_default_na=False, index_col=False)
        dv_oids = {}
        for i, row in cert_policies.iterrows():
            if row["tls_dv"] == "TRUE":
                dv_oids[row["oid"]] = row["oid"]
        feature = []
        for i, row in sample.iterrows():
            item = row["Extension_OIDs"]
            if not item:
                feature.append(-1)
            else:
                oids = ast.literal_eval(item)
                flag = False
                for oid in oids:
                    if oid in dv_oids:
                        feature.append(1)
                        flag = True
                        break
                if not flag:
                    feature.append(0)
        return feature

    @staticmethod
    def _fe_is_individual_validated(sample):
        cert_policies = pd.read_csv(FEATURE_PATHS["cert_policies"], keep_default_na=False)
        iv_oids = {}
        for i, row in cert_policies.iterrows():
            if row["tls_iv"] == "TRUE":
                iv_oids[row["oid"]] = row["oid"]
        feature = []
        for i, row in sample.iterrows():
            item = row["Extension_OIDs"]
            if not item:
                feature.append(-1)
            else:
                oids = ast.literal_eval(item)
                flag = False
                for oid in oids:
                    if oid in iv_oids:
                        feature.append(1)
                        flag = True
                        break
                if not flag:
                    feature.append(0)
        return feature

    @staticmethod
    def _fe_is_self_signed(sample):
        feature = []
        for i, row in sample.iterrows():
            if not row["Extension_Subject_Key_Identifier"]:
                feature.append(-1)
            else:
                if not row["Extension_Authority_Key_Identifier"]:
                    feature.append(1)
                else:
                    if row["Extension_Authority_Key_Identifier"] == row["Extension_Subject_Key_Identifier"]:
                        feature.append(1)
                    else:
                        feature.append(0)
        return feature


if __name__ == "__main__":
    f = PhishFeatures()
    cert_info = {
        "Url": [],
        "Cert": [],
        "Response_Time": [],
        "MD5": [],
        "SHA1": [],
        "SHA-256": [],
        "Text": [],
        "Signature_Algorithm": [],
        "Public_Key_Algorithm": [],
        "Public_Key_Length": [],
        "Issuer_Count": [],
        "Issuer_Country": [],
        "Issuer_State_Province": [],
        "Issuer_Organization": [],
        "Issuer_Organizational_Unit": [],
        "Issuer_Common_Name": [],
        "Issuer_Location": [],
        "Issuer_Email_Address": [],
        "Issuer_Length": [],
        "Issuer_All": [],
        "Subject_Count": [],
        "Subject_Country": [],
        "Subject_State_Province": [],
        "Subject_Organization": [],
        "Subject_Organizational_Unit": [],
        "Subject_Common_Name": [],
        "Subject_Location": [],
        "Subject_Email_Address": [],
        "Subject_Length": [],
        "Subject_All": [],
        "Not_Before": [],
        "Not_After": [],
        "Validity_Days": [],
        "Is_Expired": [],
        "Extension_Count": [],
        "Extension_CA": [],
        "Extension_Subject_Alt_Names": [],
        "Extension_OIDs": [],
        "Extension_Authority_Key_Identifier": [],
        "Extension_Subject_Key_Identifier": [],
        "Extension_All": [],
        "Extraction_Time": [],
    }
    dataset = f.compute_features(pd.DataFrame(cert_info))
