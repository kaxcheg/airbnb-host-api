"""Initialization tests"""
import unittest

from airbnb_host_api.airbnb import Airbnb
from airbnb_host_api.base import InvalidParameterError, AuthenticationError
from .common import BasicAirbnbTesting, write_private_data_to_file
from .common import some_wrong_email, captcha_email, some_password, some_auth_token, some_api_key

class TestAirbnbCredentialsInit(BasicAirbnbTesting):
    """
        Positive tests of initialization with Selenium.
        
        Provide json file ("tests/private_data.json" by default, see common.PRIVATE_DATA_FILE_PATH) with 
        valid email and password. See tests/private_data_template.json for structure of a private data file. 
        test_init_basic and test_init_otp, if succeeded, write auth_token and api_key values to json file.
    """
    @classmethod
    def setUpClass(cls):
        cls.read_private_data_to_class('email', 'password')

    def test_init_basic(self):
        api = Airbnb(email=self.email, password=self.password)
        auth_token_value = api.access_auth_token()
        api_key_value = api.access_api_key()
        self.basic_assert_auth_data(auth_token_value, api_key_value)
        write_private_data_to_file(auth_token=auth_token_value, api_key=api_key_value)

    def test_init_with_api_key(self):
        api = Airbnb(email=self.email, password=self.password, api_key=some_api_key)
        auth_token_value = api.access_auth_token()
        api_key_value = api.access_api_key()
        self.basic_assert_auth_data(auth_token_value, api_key_value)
        self.assertEqual(some_api_key, api_key_value, f'api_key was set to {api_key_value}, expected {some_api_key}')

class TestAirbnbAuthDataInit(BasicAirbnbTesting):
    """Positive tests of initialization with auth data"""
    def test_init_with_auth_data(self):
        api = Airbnb(auth_token=some_auth_token, api_key=some_api_key)
        auth_token_value = api.access_auth_token()
        api_key_value = api.access_api_key()
        self.basic_assert_auth_data(auth_token_value, api_key_value)
        self.assertEqual(some_auth_token, auth_token_value, f'auth_token were set to {auth_token_value}, expected {some_auth_token}')
        self.assertEqual(some_api_key, api_key_value, f'api_key was set to {api_key_value}, expected {some_api_key}')

class TestAirbnbInitExceptions(unittest.TestCase):
    """Negative exceptive initialization tests"""
    def test_basic_init_exceptions(self):
        test_cases = [
            {
                "exception": InvalidParameterError,
                "init_kwargs": {},
                "msg": "Wrong usage: provide nonblank values for email, password and optional api_key OR "
                    "auth_token and api_key"
            },
            {
                "exception": InvalidParameterError,
                "init_kwargs": {"email": some_wrong_email},
                "msg": "Wrong usage: provide nonblank values for email, password and optional api_key OR "
                    "auth_token and api_key"
            },
            {
                "exception": InvalidParameterError,
                "init_kwargs": {"password": some_password},
                "msg": "Wrong usage: provide nonblank values for email, password and optional api_key OR "
                    "auth_token and api_key"
            },
            {
                "exception": AuthenticationError,
                "init_kwargs": {"email": some_wrong_email, "password": some_password},
                "msg": "Wrong email."
            },
            {
                "exception": AuthenticationError,
                "init_kwargs": {"email": captcha_email, "password": some_password},
                "msg": "Captha detected."
            },
            {
                "exception": InvalidParameterError,
                "init_kwargs": {"auth_token": some_auth_token},
                "msg": "Wrong usage: provide nonblank values for email, password and optional api_key OR "
                    "auth_token and api_key"
            },
            {
                "exception": InvalidParameterError,
                "init_kwargs": {"api_key": some_api_key},
                "msg": "Wrong usage: provide nonblank values for email, password and optional api_key OR "
                    "auth_token and api_key"
            },
            {
                "exception": InvalidParameterError,
                "init_kwargs": {"email": some_wrong_email,
                                "password": some_password, 
                                "auth_token": some_auth_token, 
                                "api_key": some_api_key},
                "msg": "Wrong usage: provide nonblank values for email, password and optional api_key OR "
                    "auth_token and api_key"
            },
            {
                "exception": InvalidParameterError,
                "init_kwargs": {"auth_token": some_auth_token, "api_key": ''},
                "msg": "Wrong usage: api_key cannot be blank."
            },

        ]

        for case in test_cases:
            with self.subTest(init_kwargs=case["init_kwargs"], exception=case["exception"]):
                self.assertRaisesRegex(case["exception"], case['msg'], Airbnb, **case["init_kwargs"])

if __name__ == "__main__":
    unittest.main()