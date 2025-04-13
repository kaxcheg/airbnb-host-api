"""Basic module for booking sites APIs wrappers"""

from abc import ABC, abstractmethod
import os

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException

from requests.utils import dict_from_cookiejar

def raise_if_blank(args:dict):
    for arg_name, arg in args.items():
        if not arg:
            raise InvalidParameterError(f'Wrong usage: {arg_name} cannot be blank.')
        
def raise_auth_error_or_for_status(response, status_reason:dict, msg:str):
    if response.status_code in status_reason and status_reason[response.status_code] == response.reason:
        raise AuthenticationError(msg)
    else:
        response.raise_for_status()
        
def raise_scraping_error(locators, original_exception, extra_raise_condition = None):
    msg = f'{extra_raise_condition} and none of expected locators: {locators} were not found.' \
        if extra_raise_condition else f'None of expected locators: {locators} were not found.'
    raise ScrapingError(msg) from original_exception

class InvalidParameterError(Exception):
    """Thrown if wrong usage option is used."""
    pass

class AuthenticationError(Exception):
    """
        Thrown if authentication error during scraping initialization (wrong credentials, too many OTP input attempts etc.) 
        or if auth data is expired or nonvalid.
    """
    pass

class ScrapingError(Exception):
    """Thrown if expected selenium locators or auth data is not found."""
    pass

class BaseScraping(ABC):
    """Basic Selenium class for automated login."""
    def __init__(
            self, 
            email:str,
            password:str,
            browser_args:list|None=None, 
            page_load_strategy:str|None = None  
            ) -> None:
        """Starts Selenium driver and logs in using _login method in child class."""

        options = Options()
        if browser_args is not None:
            for argument in browser_args:
                options.add_argument(argument)
        options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) " 
                            "AppleWebKit/537.36 (KHTML, like Gecko) " 
                            "Chrome/113.0.0.0 Safari/537.36")
        if page_load_strategy is not None:
            options.page_load_strategy = page_load_strategy

        # selenium logs are switched off by default
        options.add_experimental_option('excludeSwitches', ['enable-logging'])
        service = Service(log_path=os.devnull)

        self.driver = webdriver.Chrome(service=service, options=options)
        # hiding
        self.driver.execute_cdp_cmd("Page.addScriptToEvaluateOnNewDocument", {
            "source": "Object.defineProperty(navigator, 'webdriver', {get: () => undefined})"
            })
        
        self._email = email
        self._password = password

        try:
            self._login()
        finally:
            self.driver.quit()

    @abstractmethod
    def _login(self):
        """Stub method. Implement this method in child class."""
        pass
    
    def _update_cookies(self):
        received_cookies = dict_from_cookiejar(self._session.cookies)
        if received_cookies != self._cookies:
            self._cookies = received_cookies

    def _is_locator_found(self, locator:tuple, timeout:float) -> bool:
        try:
            WebDriverWait(self.driver, timeout).until(EC.presence_of_element_located(locator))
        except TimeoutException:
            return False
        return True