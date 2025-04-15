"""Simple API for host at Airbnb"""
from decimal import Decimal, InvalidOperation
import re
from datetime import datetime, timedelta, date
import requests
from requests.exceptions import JSONDecodeError
from requests.utils import dict_from_cookiejar
from typing import Literal, TypedDict

from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC 
from selenium.common.exceptions import TimeoutException

from .base import BaseScraping, InvalidParameterError, AuthenticationError, ScrapingError, raise_if_blank, raise_auth_error_or_for_status, raise_scraping_error
from . import airbnb_locators as locators
from .config import ELEMENT_WAIT_TIMEOUT, SETUP_WAIT_TIMEOUT, RESERVATION_ENTRIES_LIMIT

class AirbnbReservation(TypedDict):
    confirmation_code: str
    start_date: date
    end_date: date
    listing_id: int
    listing_name: str
    booked_date: date
    nights: int
    guest_name: str
    contact: str
    adults: int
    children: int
    infants: int
    earnings: Decimal 
    invoice_ids: list[str] 
    status: str

    @classmethod
    def normalize(cls, reservation: "AirbnbReservation") -> dict[str, str|int|list]:
        """
          - date -> ISO (YYYY-MM-DD)
          - Decimal -> str
        """
        return {
            "confirmation_code": reservation["confirmation_code"],
            "start_date": reservation["start_date"].isoformat(),
            "end_date": reservation["end_date"].isoformat(),
            "listing_id": reservation["listing_id"],
            "listing_name": reservation["listing_name"],
            "booked_date": reservation["booked_date"].isoformat(),
            "nights": reservation["nights"],
            "guest_name": reservation["guest_name"],
            "contact": reservation["contact"],
            "adults": reservation["adults"],
            "children": reservation["children"],
            "infants": reservation["infants"],
            "earnings": str(reservation["earnings"]),
            "invoice_ids": reservation["invoice_ids"],
            "status": reservation["status"],
        }


class ApiKeyException(Exception):
    """Thrown when native API data could not be retrieved"""
    pass

class AuthTokenException(Exception):
    """Thrown when auth token could not be retrieved"""
    pass

class Airbnb(BaseScraping):
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

    If you get 401 error ("Unauthorized"), while running get_reservations() or other requiring authentication methods, 
    update auth token::

        api = Airbnb(email='user@domain.com', password='qwerty', api_key=api_key) 
        new_auth_token = api.access_auth_token()

    In case you get 400 error ("Bad Request" - this one should be rare), update API key (auth token will be also updated)::

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
        # init with nonblank auth data
        if auth_token is not None and api_key is not None and email is None and password is None:
            raise_if_blank({'auth_token': auth_token, 'api_key': api_key})
            self._auth_token = auth_token
            self._api_key = api_key

        # init with nonblank credentials
        elif email is not None and password is not None and auth_token is None:
            raise_if_blank({'email': email, 'password': password})
            if api_key is not None:
                raise_if_blank({'api_key': api_key})
            
            self._auth_token = None
            # api_key is None or truthy
            self._api_key = api_key

            if browser_args is None:
                browser_args = [
                    '--disable-gpu',
                    '--headless'
                ]
            
            # login and setup auth data (auth_token, api_key if needed) with Selenium
            super().__init__(
                email=email,
                password=password,
                browser_args=browser_args, 
                page_load_strategy=page_load_strategy,
                )
            
        # other init options are wrong usage
        else:
            raise InvalidParameterError('Wrong usage: provide nonblank values for email, password and optional api_key OR '
                'auth_token and api_key')
        
        # checking if attributes are truthy
        if not self._auth_token:
            raise ScrapingError('Scraping failed: auth_token value was not set.')
        if not self._api_key:
            raise ScrapingError('Scraping failed: api_key value was not set.')

        # Initializing requests session. Check what headers can be deleted
        self._session = requests.Session()
        self._session.headers = {
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        }
        self._session.cookies.update(self._auth_token)
        self._session.headers.update({locators.api_key_header_name: self._api_key})

    def access_auth_token(self):
        """Returns auth token"""
        return self._auth_token
    
    def access_api_key(self):
        """Returns native Airbnb API key."""
        return self._api_key
    
    def _email_login(self):
        def setup(driver):
            if not self._auth_token:
                auth_token = {}
                cookies = driver.get_cookie(locators.auth_token_name)
                if cookies and 'value' in cookies:
                    auth_token[locators.auth_token_name] = cookies['value']
                    self._auth_token = auth_token

            if not self._api_key:
                match = re.search(locators.api_key_re, self.driver.page_source)
                if match:
                    self._api_key = match.group(1)

            if self._auth_token and self._api_key:
                return True
            
            return False

        driver = self.driver
        driver.get(locators.login_url)
        self._hide_cookies_window()

        wait_for_element = WebDriverWait(driver, ELEMENT_WAIT_TIMEOUT)
       
        try:
            wait_for_element.until(EC.element_to_be_clickable(locators.email_button_xpath)).click()
        except TimeoutException as e:
            raise_scraping_error(locators.email_button_xpath, e)

        try:
            wait_for_element.until(EC.presence_of_element_located(locators.email_field_id)).send_keys(self._email)
        except TimeoutException as e:
            raise_scraping_error(locators.email_field_id, e)


        try:
            wait_for_element.until(EC.element_to_be_clickable(locators.continue_button_xpath)).click()
        except TimeoutException as e:
            raise_scraping_error(locators.continue_button_xpath, e)
        
        try:
            send_email_result = wait_for_element.until(EC.any_of(
                EC.presence_of_element_located(locators.password_field_id), 
                EC.presence_of_element_located(locators.captcha_detected_id),
                EC.presence_of_element_located(locators.invalid_email_domain_id)
                ))
        except TimeoutException as e:
            raise_scraping_error((locators.password_field_id, locators.captcha_detected_id, locators.invalid_email_domain_id), e)
        
        if send_email_result.get_attribute('id') == locators.invalid_email_domain_id[1]:
            raise AuthenticationError('Wrong email.')
        
        if send_email_result.get_attribute('id') == locators.captcha_detected_id[1]:
            raise AuthenticationError('Captha detected.')
        
        password_field = send_email_result
        del send_email_result

        password_field.send_keys(self._password)

        try:
            wait_for_element.until(EC.element_to_be_clickable(locators.continue_button_xpath)).click()
        except TimeoutException as e:
            raise_scraping_error(locators.continue_button_xpath, e)
        
        try:
            signin_result = WebDriverWait(driver, SETUP_WAIT_TIMEOUT).until(
                    lambda driver: setup(driver) or EC.any_of(
                        EC.presence_of_element_located(locators.invalid_password_len_id),
                        EC.presence_of_element_located(locators.invalid_password_css_selector)
                    )(driver))
        except TimeoutException as e:
            raise_scraping_error((locators.invalid_password_len_id, locators.invalid_password_css_selector), e, extra_raise_condition='Failed to setup')

        # setup was successfully run and returned bool type (True)
        if isinstance(signin_result, bool):         
            return
        
        elif signin_result.get_attribute('id') == locators.invalid_password_len_id[1]:
            raise AuthenticationError('Wrong password. Invalid lengh.')
            
        elif signin_result.get_attribute('class') == locators.invalid_password_css_selector[1]:
            raise AuthenticationError('Wrong password.')

    def _login(self):
        """Logs in and sets auth_token and api_key"""
        self._email_login()

    def _update_auth_token_from_cookies(self):
        all_cookies = dict_from_cookiejar(self._session.cookies)
        auth_token = {name: value for name, value in all_cookies.items() if name == locators.auth_token_name}
        if auth_token != self._auth_token:
            self._auth_token = auth_token

    def get_reservations(
            self,  
            status: Literal['upcoming','completed','canceled','all']='all',
            listing_id:int = None, 
            date_min:str = None,   
            date_max:str = None,
            confirmation_code:str=None,
            return_normalized = False
            ) -> list[AirbnbReservation]|AirbnbReservation:
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
            "earnings": Decimal
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
        def process_reservation(entry: dict):
            try:
                reservation: AirbnbReservation = {
                    "confirmation_code": entry["confirmation_code"],
                    "start_date": datetime.strptime(entry["start_date"], "%Y-%m-%d").date(),
                    "end_date": datetime.strptime(entry["end_date"], "%Y-%m-%d").date(),
                    'listing_id': entry['listing_id'],
                    "listing_name": entry["listing_name"],
                    "booked_date": datetime.strptime(entry["booked_date"], "%Y-%m-%d").date(),             
                    "nights": entry["nights"],
                    "guest_name": entry["guest_user"].get('full_name', entry["guest_user"]['first_name']),
                    "contact": re.sub(r'\s+', '', entry["guest_user"].get('phone', '')),
                    "adults": entry["guest_details"]['number_of_adults'],
                    "children": entry["guest_details"]['number_of_children'],
                    "infants": entry["guest_details"]['number_of_infants'],
                    "earnings": Decimal(entry["earnings"].replace('\xa0', '').replace('\u20AC', '').replace(',', '')),
                    'invoice_ids': [invoice['invoice_number'] for invoice in entry['host_vat_invoices']],
                    "status": entry["user_facing_status_localized"],
                    }
                
            except (KeyError, ValueError, InvalidOperation, IndexError) as e:
                raise ValueError('Unexpected response.') from e        
            
            return reservation
        
        limit = RESERVATION_ENTRIES_LIMIT
    
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

        all_reservations = []

        try:
            while total_count is None or offset < total_count:
                params["_offset"] = offset
                response = self._session.get(locators.api_reservations_url, params=params)
                raise_auth_error_or_for_status(response, {
                    401: 'Unauthorized', 
                    400: 'Bad Request'},
                    'auth_token or api_key are expired or nonvalid. Update running with an email and password.')
                self._update_auth_token_from_cookies()
                response_json = response.json()

                for entry in response_json['reservations']:
                    reservation = process_reservation(entry=entry)
                    if confirmation_code is not None and reservation['confirmation_code'] == confirmation_code:
                            return reservation
                    all_reservations.append(reservation)

                if total_count is None:
                    total_count = response_json['metadata']['total_count']
                offset += limit
        except (KeyError, JSONDecodeError) as e:
            raise ValueError('Unexpected response.') from e

        if return_normalized:
            all_reservations_normalized = [AirbnbReservation.normalize(reservation) for reservation in all_reservations]
            return all_reservations_normalized
        else:
            return all_reservations 
    
    def get_host_fees(self, invoice_ids:list[str] = None, confirmation_code:str = None, return_normalized = False) -> dict:
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
            raise_auth_error_or_for_status(response, {
                    401: 'Unauthorized', 
                    400: 'Bad Request'},
                    'auth_token or api_key are expired or nonvalid. Update running with an email and password.')
            self._update_auth_token_from_cookies()

            pattern = r"<td[^>]*>.*?(\d+\.\d+).*?</td>"
            matches = re.findall(pattern, response.text, re.S)

            if len(matches) == 3:
                return {
                    "base_service_fee": Decimal(matches[0]),
                    "VAT": Decimal(matches[1]),
                    "total_service_fee": Decimal(matches[2])
                }
            else:
                raise ScrapingError(f"Unexpected response structure: expected 3 fee values, got {len(matches)}")
        
        if invoice_ids is None:
            if confirmation_code is None:
                raise InvalidParameterError('One of invoice_ids or confirmation_code arguments should be provided')
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
        if return_normalized:
            return {key: str(val) for key, val in total_fees.items()}
        else:
            return total_fees
    
    def get_ics_calendar(self, listing_id:int):
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
        raise_auth_error_or_for_status(calendar_uri, {
                    401: 'Unauthorized', 
                    400: 'Bad Request'},
                    'auth_token or api_key are expired or nonvalid. Update running with an email and password.')
        self._update_auth_token_from_cookies()
        try:
            calendar_uri_json = calendar_uri.json()
        except JSONDecodeError as e:
            raise ValueError('Unexpected response.') from e
        
        try:
            calendar = self._session.get(locators.api_base_url+calendar_uri_json['listing']['ical_uri'])
        except (KeyError, JSONDecodeError) as e:
            raise ValueError('Unexpected response.') from e
        
        raise_auth_error_or_for_status(calendar, {
                    401: 'Unauthorized', 
                    400: 'Bad Request'},
                    'auth_token or api_key are expired or nonvalid. Update running with an email and password.')
        self._update_auth_token_from_cookies()

        return calendar.text

    def _hide_cookies_window(self) -> None:
        driver = self.driver
        try:
            cookie_window = WebDriverWait(driver, ELEMENT_WAIT_TIMEOUT*10).until(
                EC.presence_of_element_located(locators.cookies_window_xpath)
                )
        except TimeoutException as e:
            raise_scraping_error(locators.cookies_window_xpath, e)
        
        driver.execute_script("arguments[0].style.display = 'none';", cookie_window)