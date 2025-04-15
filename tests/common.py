PRIVATE_DATA_FILE_PATH = "tests/private_data.json"

import json
import unittest
from filelock import FileLock

import airbnb_host_api.airbnb_locators as locators

lock = FileLock("PRIVATE_DATA_FILE_PATH")

some_wrong_email = 'email'
captcha_email = 'email@gmail.com'
some_password = 'pass'
some_auth_token = {locators.auth_token_name: 'some_value'}
some_api_key = 'some_value'

def compare_dicts(dict1: dict, dict2: dict, dict1_name, dict2_name) -> None:
    """
        Compare {dict1_name} and {dict1_name} and print the differences in keys and values.
    """
    keys1 = set(dict1.keys())
    keys2 = set(dict2.keys())

    only_in_dict1 = keys1 - keys2
    only_in_dict2 = keys2 - keys1
    common_keys = keys1 & keys2

    if only_in_dict1:
        print(f"🔴 Keys only in {dict1_name}: {only_in_dict1}")
    if only_in_dict2:
        print(f"🔵 Keys only in {dict2_name}: {only_in_dict2}")

    value_differences = {key: (dict1[key], dict2[key]) for key in common_keys if dict1[key] != dict2[key]}

    if value_differences:
        print("⚠️ Value differences:")
        for key, (val1, val2) in value_differences.items():
            print(f"  🔸 Key '{key}': {dict1_name}={val1} | {dict2_name}={val2}")

    if not (only_in_dict1 or only_in_dict2 or value_differences):
        print("✅ The dictionaries are identical.")

def get_OTP_from_input(msg):
    OTP = ''
    while not OTP:
        OTP = input(msg)
    return OTP

def write_private_data_to_file(**kwargs):
    with open(PRIVATE_DATA_FILE_PATH, "r") as f:
        data = json.load(f)
    
    data.update({key: value for key, value in kwargs.items() if value})

    with lock:
        with open(PRIVATE_DATA_FILE_PATH, 'w') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)

def read_private_data(key):
    with open(PRIVATE_DATA_FILE_PATH, "r") as f:
            secrets = json.load(f)

    return secrets[key]

class BasicAirbnbTesting(unittest.TestCase):
    @classmethod
    def read_private_data_to_class(cls, *args):
        with open(PRIVATE_DATA_FILE_PATH, "r") as f:
                secrets = json.load(f)

        for arg in args:
             setattr(cls, arg, secrets[arg])
 
    def basic_assert_auth_data(self, auth_token_value, api_key_value):  
        self.assertTrue(auth_token_value, "auth_token should not be blank")
        self.assertTrue(api_key_value, "api_key should not be blank")
        self.assertIsInstance(auth_token_value, dict, "auth_token should be a dict")
        self.assertIsInstance(api_key_value, str, "api_key should be an string")