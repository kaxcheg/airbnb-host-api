"""Host methods tests"""
import unittest

from airbnb_host_api.airbnb import Airbnb
from airbnb_host_api.base import AuthenticationError

from .common import BasicAirbnbTesting, write_private_data_to_file, read_private_data, compare_dicts
from .common import some_auth_token, some_api_key

class TestAirbnbMethods(BasicAirbnbTesting):
    """
        Positive methods test.
        
        Provide json file ("tests/private_data.json" by default, see common.PRIVATE_DATA_FILE_PATH) with 
        valid auth_token and api_key and test cases data. See tests/private_data_template.json for 
        structure of a private data file.

        Run test_init_basic or test_init_otp before running tests to write valid 
        auth_token and api_key in the private file or put them manually. 
    """
    @classmethod
    def setUpClass(cls):
        cls.read_private_data_to_class('auth_token', 'api_key')
        cls.api = Airbnb(auth_token=cls.auth_token, api_key=cls.api_key)   

    def test_get_reservations(self):
        test_cases:list[dict] = read_private_data('get_reservations_cases')

        for case in test_cases: 
            case_num = case.pop('case_num')
            with self.subTest(case_number=case_num):
                expected_number = case.pop('expected_number')
                expected_reservations = case.pop('expected_reservations')
                result = self.api.get_reservations(**case)
                write_private_data_to_file(auth_token=self.api.access_auth_token(), api_key=self.api.access_api_key())
                if isinstance(result, list):
                    received_number = len(result)
                    self.assertEqual(
                        received_number, 
                        expected_number, 
                        f'Expected {expected_number} reservations and got {received_number}.'
                        )

                    for expected_reservation in expected_reservations:
                        for reservation in result:
                                if expected_reservation['confirmation_code'] == reservation['confirmation_code']:
                                    try:
                                        self.assertEqual(
                                            expected_reservation, 
                                            reservation, 
                                            f"Expected reservation {expected_reservations} and got {reservation} for case #{case_num}"
                                            )
                                    # assertion is intercepted and differences are printed out
                                    except AssertionError as e:
                                        print(f'Case num {case_num}: expected and returned reservation for booking number {expected_reservation['confirmation_code']} differ:')
                                        compare_dicts(expected_reservation, reservation, 'expected reservation', 'returned reservation')
                elif isinstance(result, dict):
                    try:
                        self.assertEqual(
                            expected_reservations, 
                            result, 
                            f"Expected reservation {expected_reservations} and got {result} for case #{case_num}"
                            )
                    # assertion is intercepted and differences are printed out
                    except AssertionError as e:
                        print(f'Case num {case_num}: expected and returned reservation for booking number {expected_reservations['confirmation_code']} differ:')
                        compare_dicts(expected_reservations, result, 'expected reservation', 'returned reservation')

    def test_get_host_fees(self):
        test_cases:list[dict] = read_private_data('get_host_fees_cases')

        for case in test_cases: 
            case_num = case.pop('case_num')
            with self.subTest(case_number=case_num):
                expected_fees = case.pop("expected_fees")
                fees = self.api.get_host_fees(**case)
                self.assertEqual(expected_fees, fees, f"Expected fees {expected_fees} and got {fees} for case #{case_num}")

    def test_get_ics_calendar(self):
        test_cases:list[dict] = read_private_data('get_ics_calendar_cases')

        for case in test_cases: 
            case_num = case.pop('case_num')
            with self.subTest(case_number=case_num):
                listing_id = case.pop("listing_id")
                calendar = self.api.get_ics_calendar(listing_id)
                # most basic assertion is made
                assert calendar, 'Calendar is blank.'

class TestAirbnbMethodsExceptions(BasicAirbnbTesting):
    """
        Negative exceptive methods test.
        
        Provide json file ("tests/private_data.json" by default, see common.PRIVATE_DATA_FILE_PATH) with 
        valid auth_token and api_key. See tests/private_data_template.json for 
        structure of a private data file.
    """
    @classmethod
    def setUpClass(cls):
        cls.read_private_data_to_class('auth_token', 'api_key')

    def test_methods_exceptions(self):
        test_cases = [
            {   
                "init_kwargs": {
                    'auth_token': some_auth_token, 
                    'api_key': self.api_key,
                    },
                'msg': 'auth_token or api_key are expired or nonvalid. Update running with an email and password.'
            },
            {   
                "init_kwargs": {
                    'auth_token': self.auth_token, 
                    'api_key': some_api_key,
                    },
                'msg': 'auth_token or api_key are expired or nonvalid. Update running with an email and password.'
            },
        ]
        
        some_date_min = '2024-09-01'
        some_date_max = '2025-02-13'

        for case in test_cases:
            msg = case['msg']
            api = Airbnb(**case['init_kwargs'])
            with self.subTest(case=case['init_kwargs']):         
                self.assertRaisesRegex(AuthenticationError, msg, api.get_reservations, date_min=some_date_min, date_max=some_date_max)

if __name__ == "__main__":
    unittest.main()