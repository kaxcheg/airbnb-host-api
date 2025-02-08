"""Locators, urls and native Airbnb API parameters"""
from selenium.webdriver.common.by import By
login_url = 'https://www.airbnb.co.uk/login?redirect_url=%2Faccount-settings'

cookies_window_xpath = (By.XPATH, "//div[@data-testid='main-cookies-banner-container']")
email_button_xpath = (By.XPATH, '//button[@data-testid="social-auth-button-email"]')
email_field_id = (By.ID, 'email-login-email')
invalid_email_domain_xpath = (By.XPATH, "//div[contains(text(), 'nvalid email')]")
captcha_detected_id = (By.ID, 'arkose-modal-container-id')
invalid_password_len_id = (By.ID, 'email-signup-password-field-error')
invalid_password_css_selector = (By.CSS_SELECTOR, ".m1us9lga.hgmykkp.dir.dir-ltr")
password_field_id = (By.ID, 'email-signup-password')
continue_button_xpath = (By.XPATH, "//button[@data-testid='signup-login-submit-btn']")
auth_token_name = '_aat'

api_key_json_id = (By.ID, 'data-bootstrap')
api_key_re = r'"api_config":\{"key":"([^"]+)"'
api_key_header_name = "x-airbnb-api-key"
api_base_url = 'https://www.airbnb.co.uk'
api_reservations_url = api_base_url+"/api/v2/reservations"
api_invoice_url = api_base_url+'/vat_invoices'
api_calendar_url = api_base_url+'/api/v2/listings'