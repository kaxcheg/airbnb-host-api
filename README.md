# Airbnb API wrapper (for hosts)

## Disclaimer
This is a unofficial python API wrapper for airbnb.com. At the moment only methods for hosts are implemented.
Provides access with login(email) and password to host reservations, fees and calendar.

Using this software might contradict airbnb.com terms of service. Use in educational purpose only.

## Requirements
- selenium
- requests

## Install
pip install airbnb-host-api

## Usage
```
from airbnb_host_api import Airbnb
```
### Initial run (slow, uses Selenium to get auth token and API key)
```
api = Airbnb(email='user@domain.com', password='qwerty')    
auth_token = api.access_auth_token() 
api_key = api.access_api_key()
```
You may skip credentials check (faster):
```
api = Airbnb(email='user@domain.com', password='qwerty', credentials_check=False)
```
### Further runs (fast, doesn`t require Selenium)
```
api = Airbnb(auth_token=auth_token, api_key=api_key)
```
If you get 401 error ("authentication_required"), while running get_reservations() or other requiring authentication methods, 
update auth token:
```
api = Airbnb(email='user@domain.com', password='qwerty', api_key=api_key) 
new_auth_token = api.access_auth_token()
```
In case you get 400 error ("invalid_key" - this one should be rare), update API key (auth token will be also updated):
```
api = Airbnb(email='user@domain.com', password='qwerty') 
new_auth_token = api.access_auth_token()
new_api_key = api.access_api_key()
```
### Running methods examples
```
api.get_reservations()
api.get_reservations(date_min='2024-12-01', date_max='2024-12-31')
api.get_reservations(status='upcoming')         
api.get_reservations(status='completed', listing_id=1298231212340118374)
api.get_reservations(date_min='2024-11-01', date_max='2025-01-15', status='canceled')
api.get_host_fees(confirmation_code="ZMAB0FZABY")
api.get_host_fees(invoice_ids=["1012647776", "1030511337"])
api.get_calendar(listing_id=1298761234240118374)
```