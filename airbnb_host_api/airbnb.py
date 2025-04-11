"""Simple API for host at Airbnb"""
import decimal
import re
from datetime import datetime, timedelta
import requests
from typing import Literal

from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC 
from selenium.common.exceptions import TimeoutException

from .base import SeleniumLogin, InvalidParameterException
from . import airbnb_locators as locators

class ApiKeyException(Exception):
    """Thrown when native API data could not be retrieved"""
    pass

class AuthTokenException(Exception):
    """Thrown when auth token could not be retrieved"""
    pass

class Airbnb(SeleniumLogin):
    """
    Main Airbnb API class. 
    Provides access with login(email) and password to host reservations, fees and calendar.
    
    Usage:
    
    Initial run (slow, uses Selenium to get auth token and API key)::

        api = Airbnb(email='user@domain.com', password='qwerty')    
        auth_token = api.access_auth_token() 
        api_key = api.access_api_key()
    
    You may skip credentials check in Selenium (faster)::

        api = Airbnb(email='user@domain.com', password='qwerty', credentials_check = False)

    Further runs (fast, doesn`t use Selenium)::

        api = Airbnb(auth_token=auth_token, api_key=api_key)

    If you get 401 error ("authentication_required"), while running get_reservations() or other requiring authentication methods, 
    update auth token::

        api = Airbnb(email='user@domain.com', password='qwerty', api_key=api_key) 
        new_auth_token = api.access_auth_token()

    In case you get 400 error ("invalid_key" - this one should be rare), update API key (auth token will be also updated)::

        api = Airbnb(email='user@domain.com', password='qwerty') 
        new_auth_token = api.access_auth_token()
        new_api_key = api.access_api_key()
    """

    def __init__(
            self, 
            browser_args:list|None = None, 
            page_load_strategy:str|None = 'none',
            email:str|None = None,
            password:str|None = None,
            auth_token:dict|None = None,
            api_key:str|None = None,
            credentials_check:bool = True
            ) -> None:
        """
        Sets auth token and API key by running the Selenium driver to log in if needed, sets requests session parameters.

        Args:
        - browser_args, page_load_strategy: Selenium session arguments. By default browser_args will be ['--disable-gpu', '--headless']. 
        Pass browser_args=[] to run Selenium defaults.
        - email, password: credentials for Airbnb.
        - auth_token, api_key: provided with access_auth_token() and access_api_key() methods after initializing instance with credentials; 
        used to initialize instance for further use.
        - credentials_check: set False to ignore credentials check in Selenium login (faster). Does not throw InvalidParameterException, 
        if invalid credentials are provided (in this case you will receive AuthTokenException or Selenium TimeoutException).
        """
        # Get auth token and API key needed for native API Airbnb requests. 
        if auth_token is None or api_key is None:
            # Set credentials
            self._email = email
            self._password = password
            # Set credentials check parameter
            self._credentials_check = credentials_check
            
            try:
                if browser_args is None:
                    browser_args = [
                        '--disable-gpu',
                        '--headless',
                    ]
                # Login with Selenium and set auth token    
                super().__init__(browser_args=browser_args, page_load_strategy=page_load_strategy)
                # Set API key
                if api_key is None:
                    try:
                        WebDriverWait(self.driver, ELEMENT_WAIT_TIMEOUT).until(
                            EC.presence_of_element_located(locators.api_key_json_id)
                        )
                    except TimeoutException as e:
                        raise ApiKeyException('API json data is not found') from e
                    
                    match = re.search(locators.api_key_re, self.driver.page_source)
                    if match is not None and match.group(1):
                        self._api_key = match.group(1)
                    else:
                        raise ApiKeyException("API key is not found in json data")
                else:
                    self._api_key = api_key
            finally:
                self.driver.quit()

        else:
            self._auth_token = auth_token
            self._api_key = api_key      

        # Initializing requests session
        self._session = requests.Session()
        self._session.headers = {
            "accept": "*/*",
            "accept-encoding": "gzip, deflate, br, zstd",
            "sec-ch-ua": "\"Google Chrome\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"",
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": "\"Windows\"",
            "sec-ch-ua-platform-version": "\"10.0.0\"",
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "x-airbnb-supports-airlock-v2": "true",
            "x-csrf-token": "",
            "x-csrf-without-token": "1"
        }
        self._session.cookies.update(self._auth_token)
        self._session.headers.update({locators.api_key_header_name: self._api_key})

    def access_auth_token(self):
        """Returns auth token"""
        return self._auth_token
    
    def access_api_key(self):
        """Returns native Airbnb API key."""
        return self._api_key
    
    def _email_login(self) -> dict:
        driver = self.driver
        driver.get(locators.login_url)
        self._hide_cookies_window()
       
        WebDriverWait(driver, ELEMENT_WAIT_TIMEOUT).until(
            EC.element_to_be_clickable(locators.email_button_xpath)
            ).click()

        WebDriverWait(driver, ELEMENT_WAIT_TIMEOUT).until(
            EC.presence_of_element_located(locators.email_field_id)
        ).send_keys(self._email)
        WebDriverWait(driver, ELEMENT_WAIT_TIMEOUT).until(
            EC.element_to_be_clickable(locators.continue_button_xpath)
        ).click()
        if self._credentials_check:
            if self._is_locator_found(locator=locators.captcha_detected_id) or self._is_locator_found(locator=locators.invalid_email_domain_xpath):
                raise InvalidParameterException('Wrong email.')

        WebDriverWait(driver, ELEMENT_WAIT_TIMEOUT).until(
            EC.presence_of_element_located(locators.password_field_id)
        ).send_keys(self._password)
        WebDriverWait(driver, ELEMENT_WAIT_TIMEOUT).until(
            EC.element_to_be_clickable(locators.continue_button_xpath)
        ).click()
        if self._credentials_check:
            if self._is_locator_found(locator=locators.invalid_password_len_id) or self._is_locator_found(locator=locators.invalid_password_css_selector):
                raise InvalidParameterException('Wrong password.')
        
        try:
            cookie = WebDriverWait(driver, AUTH_TOKEN_WAIT_TIMEOUT).until(lambda d: d.get_cookie(locators.auth_token_name))
        except TimeoutException as e:
            raise AuthTokenException(f'Auth token {locators.auth_token_name} is not found.') from e
        
        auth_token = {cookie['name']: cookie['value']}
        return auth_token

    def _login(self) -> dict:
        """Logs in with Selenium browser and returns auth token dict."""
        if not self._email:
            raise InvalidParameterException('Email cannot be empty.')
        if not self._password:
            raise InvalidParameterException('Password cannot be empty.')

        auth_token = self._email_login()
        return auth_token
       
    def get_reservations(
            self,  
            status: Literal['upcoming','completed','canceled','all']='all',
            listing_id:int = None, 
            date_min:str = None,   
            date_max:str = None,
            confirmation_code:str=None
            ) -> list[dict]|dict:
        """
        Returns list of reservation dictionaries or a dictionary, if confirmation_code is provided, in the following format::

            "confirmation_code": str
            "start_date": datetime.date
            "end_date": datetime.date
            'listing_id': int
            "listing": str
            "booked_date": datetime.date            
            "nights": int
            "guest_name": str # first_name or full_name if provided 
            "contact": str
            "adults": int
            "children": int
            "infants": int
            "earnings": str
            'invoice_ids': list[str]
            "status": str

        Args:
        - status: status filter for reservations to be retrieved.
        - listing_id: can be retrieved with get_reservations() method without specifying listing_id argument. 
        - date_min, date_max: date filters in YYYY-MM-DD format.
        - confirmation_code: can be retrieved with get_reservations() method without specifying confirmation_code argument;
        if specified, other arguments are ignored.

        Usage examples::

            api.get_reservations()
            api.get_reservations(date_min='2024-12-01', date_max='2024-12-31')
            api.get_reservations(status='upcoming')         
            api.get_reservations(status='completed', listing_id=1298761212340118374)
            api.get_reservations(date_min='2024-11-01', date_max='2025-01-15', status='canceled')
        """      
        def process_reservation(entry):
            reservation = {
                "confirmation_code": entry["confirmation_code"],
                "start_date": datetime.strptime(entry["start_date"], "%Y-%m-%d").date(),
                "end_date": datetime.strptime(entry["end_date"], "%Y-%m-%d").date(),
                'listing_id': entry['listing_id'],
                "listing": entry["listing_name"],
                "booked_date": datetime.strptime(entry["booked_date"], "%Y-%m-%d").date(),             
                "nights": entry["nights"],
                "guest_name": entry["guest_user"].get('full_name', entry["guest_user"]['first_name']),
                "contact": re.sub(r'\s+', '', entry["guest_user"].get('phone', '')),
                "adults": entry["guest_details"]['number_of_adults'],
                "children": entry["guest_details"]['number_of_children'],
                "infants": entry["guest_details"]['number_of_infants'],
                "earnings": entry["earnings"].replace('\xa0', '').replace(',', ''),
                'invoice_ids': [invoice['invoice_number'] for invoice in entry['host_vat_invoices']],
                "status": entry["user_facing_status_localized"],
                }
            
            return reservation
        
        limit = API_RESERVATION_ENTRIES_LIMIT
    
        params = {
            "locale": "en-GB",
            "currency": "EUR",
            "_format": "for_remy",
            "_limit": limit,
            "collection_strategy": "for_reservations_list",
        }

        if confirmation_code is None:
            status_params_mapping = {
                'upcoming': "accepted,request",
                'completed': "accepted",
                'canceled': "canceled",
                'all': "accepted,request,canceled"
            }
            params['status'] = status_params_mapping[status]

            if listing_id is not None:
                params['listing_id'] = listing_id

            today = datetime.today().strftime('%Y-%m-%d')
            yesterday = (datetime.today() - timedelta(days=1)).strftime('%Y-%m-%d')

            if status == 'all' or status == 'canceled':
                params["sort_field"] = "start_date"
                params["sort_order"] = "desc"

            if status == 'completed':
                params['ends_before'] = yesterday
                params["sort_field"] = "end_date"
                params["sort_order"] = "desc"

            if status == 'upcoming':
                params["sort_field"] = "start_date"
                params["sort_order"] = "asc"
                params['date_min'] = min(date_min or today, today)

            if date_min is not None and status != 'upcoming':
                params['date_min'] = date_min

            if date_max is not None:
                params['date_max'] = date_max

        offset = 0
        total_count = None

        data = []

        while total_count is None or offset < total_count:
            params["_offset"] = offset
            response = self._session.get(locators.api_reservations_url, params=params)
            response.raise_for_status()
            response_json = response.json()

            for entry in response_json['reservations']:
                reservation = process_reservation(entry=entry)
                if confirmation_code is not None and reservation['confirmation_code'] == confirmation_code:
                        return reservation
                data.append(reservation)

            if total_count is None:
                total_count = response_json['metadata']['total_count']
            offset += limit

        return data
    
    def get_host_fees(self, invoice_ids:list[str] = None, confirmation_code:str = None) -> dict:
        """
        Returns dictionary with Decimals of base service fee, VAT and total service fee.
        One of two arguments, which could be obtained with get_reservations(), should be provided.
        If two are provided, invoice_ids will be used.

        Args:
        - invoice_ids: list of invoice ids - faster way. Method does not check, if ids correspond to one reservation code. 
        - confirmation_code: particular reservation code - slower way

        Usage examples::

            api.get_host_fees(confirmation_code="ZMAB0FHEBY")
            api.get_host_fees(invoice_ids=["1012647776", "1030511337"])
        """
        def get_host_fees_from_invoice(invoice_id):
            response = self._session.get(locators.api_invoice_url+'/'+invoice_id)
            response.raise_for_status()

            pattern = r"<td[^>]*>.*?(\d+\.\d+).*?</td>"
            matches = re.findall(pattern, response.text, re.S)

            if len(matches) == 3:
                return {
                    "base_service_fee": decimal.Decimal(matches[0]),
                    "VAT": decimal.Decimal(matches[1]),
                    "total_service_fee": decimal.Decimal(matches[2])
                }
            else:
                raise RuntimeError(f"Unexpected response structure: expected 3 fee values, got {len(matches)}")
        
        if invoice_ids is None:
            if confirmation_code is None:
                raise InvalidParameterException('One of invoice_ids or confirmation_code arguments should be provided')
            reservation = self.get_reservations(confirmation_code=confirmation_code)
            invoice_ids = reservation['invoice_ids']

        total_fees = {
            'base_service_fee': 0,
            "VAT": 0,
            "total_service_fee": 0
        }

        for invoice_id in invoice_ids:
            fees = get_host_fees_from_invoice(invoice_id=invoice_id)
            total_fees['base_service_fee'] += fees['base_service_fee']
            total_fees['VAT'] += fees['VAT']
            total_fees['total_service_fee'] += fees['total_service_fee']
        
        return total_fees
    
    def get_calendar(self, listing_id:int):
        """
        Returns string in ics format with calendar events for listing_id, which could be obtained with get_reservations().
        Usage example::

        api.get_calendar(listing_id=1298761212340118374)
        """
        params = {
            "locale": "en-GB",
            "_format": "for_remy_calendar_url_path",
        }

        calendar_uri = self._session.get(locators.api_calendar_url+'/'+str(listing_id), params=params)
        calendar_uri.raise_for_status()
        calendar_uri_json = calendar_uri.json()
        calendar = self._session.get(locators.api_base_url+calendar_uri_json['listing']['ical_uri'])
        calendar.raise_for_status()

        return calendar.text

    def _hide_cookies_window(self) -> None:
        driver = self.driver
        try:
            cookie_window = WebDriverWait(driver, ELEMENT_WAIT_TIMEOUT*10).until(
                EC.presence_of_element_located(locators.cookies_window_xpath)
                )
            driver.execute_script("arguments[0].style.display = 'none';", cookie_window)
        except TimeoutException as e:
            raise RuntimeError('Cookies consent window could not be found within timeout.') from e
    
    def _is_locator_found(self, locator:tuple, timeout:float=ELEMENT_WAIT_TIMEOUT):
        return super()._is_locator_found(locator, timeout)