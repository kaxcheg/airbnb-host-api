"""Basic module for booking sites custom APIs"""
from abc import ABC, abstractmethod

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException

class InvalidParameterException(Exception):
    """Thrown when invalid credentials are provided or wrong method arguments usage"""
    pass

class SeleniumLogin(ABC):
    """Basic Selenium login functionality class"""
    def __init__(self, browser_args:list|None=None, page_load_strategy:str|None = None) -> None:
        """Starts Selenium driver, logs in and initializes auth token"""
        options = Options()
        if browser_args is not None:
            for argument in browser_args:
                options.add_argument(argument)
        if page_load_strategy is not None:
            options.page_load_strategy = page_load_strategy

        self.driver = webdriver.Chrome(options=options)
        self._auth_token = self._login()

    @abstractmethod
    def _login(self):
        """Stub to ensure that _login method is implemented in child classes"""
        pass

    def _is_locator_found(self, locator:tuple, timeout:float) -> bool:
        try:
            WebDriverWait(self.driver, timeout).until(EC.presence_of_element_located(locator))
        except TimeoutException:
            return False
        return True