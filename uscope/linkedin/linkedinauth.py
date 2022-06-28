import json
import random
from flask_login import current_user, login_required
import requests
import string
from urllib.parse import urlparse, parse_qs
from  datetime import datetime 
from uscope.helper import get_key, set_key
from flask import Blueprint, flash, request
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
from models import LinkedinUser
from db import db_session

driver = webdriver.Chrome()
bp = Blueprint('lisearch', __name__, url_prefix='/lisearch')
url = 'https://www.linkedin.com'

@bp.route('/login', methods=('GET', 'POST',))
@login_required
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if (username == "") or (password == ""):
            flash('cannae log in with a blank.')
        if webpage_login(username, password):
            linkedin_user = LinkedinUser.query(LinkedinUser.user_id ==current_user.id).first()
            if linkedin_user is None:
                linkedin_user = LinkedinUser(user_id=current_user.id, username=username, password=password)
                db_session.add(linkedin_user)
            else:
                linkedin_user(username=username, password=password)
            db_session.commit()
            return linkedin_search()
        else:            
            flash('That login seems a bit off.')
            




def webpage_login(username, password):
    driver.get(url)
    if "Log in" in driver.title:
        username_input = driver.find_element(By.ID, "session_key")
        username_input.clear()
        username_input.send_keys(username)
        password_input = driver.find_element(By.ID, "session_password")
        password_input.clear()
        password_input.send_keys(password)
        password_input.submit()
        if (driver.find_element(By.ID, 'error-for-username')):
            return False
        if (driver.find_element(By.ID, 'error-for-password')):
            return False
        return True
    return False


def linkedin_search():
    return 'TODO'

def auth(credentials):
    creds = read_creds(credentials)
    print(creds)
    client_id = get_key('linkedin_client_id')
    client_secret = get_key('linkedin_client_secret')
    redirect_uri = get_key('linkedin_redirect_uri')
    api_url = 'https://www.linkedin.com/oauth/v2'
    if datetime(get_key('linkedin_timeout')) < datetime.now():
        args = client_id, client_secret, redirect_uri
        auth_code = authorize(api_url, *args)
        access_token = refresh_token(auth_code, *args)
        set_key('linkedin_access_token', access_token['access_token'])
        set_key('linkedin_timeout', str(datetime.now() + datetime.timedelta(seconds=int(access_token['expires_in']))))
    else:
        access_token = get_key('linkedin_access_token')
    return access_token

def headers(access_token):
    return {
        'Authorization': f'Bearer {access_token}',
        'cache_control': 'no-cache',
        'X-Restli-Protocol-Version' : '2.0.0'
    }

def create_CSRF_token():
    letters = string.ascii_lowercase
    token = ''.join(random.choice(letters) for i in range(20))
    return token

def open_url(url):
    '''probably want to turn this into a blueprint with a click here thingy.'''
    import webbrowser
    print(url)
    webbrowser.open(url)

def parse_redirect_uri(redirect_response):
    url = parse_qs(urlparse(redirect_response).query)
    return url['code'][0]

def authorize(api_url, client_id, client_secret, redirect_uri):
    csrf_token = create_CSRF_token()
    params = {
        'response_type': 'code',
        'client_id' : client_id,
        'redirect_uri' : redirect_uri,
        'state' : csrf_token,
        'scope' : 'r_liteprofile,remailaddress,w_membersocial' 
    }
    response = requests.get(f'{api_url}/authorization', params=params)
    open_url(response.url)
    redirect_response = input('Paste the full url here:')
    auth_code = parse_redirect_uri(redirect_response)
    return auth_code



class linkedin_search:
    logged_in = False
    
    def __init__(self, company_name, url ):
        self.login()
        for company in self.search_company(company_name):
            urllist = self.get_company_url(company)

    

    def search_company(self, companyname):
        driver.get(url + "/feed/")
        search_button = driver.find_element(By.CLASS_NAME, "search-global-typehead__collapsed-search-button")
        search_button.click()
        search_input = driver.find_element(By.CLASS_NAME, "search-global-typeahead__input always-show-placeholder always-show-paceholder")
        search_input.clear()
        search_input.send_keys(companyname)
        search_input.send_keys(Keys.RETURN)
        company_filter = driver.find_element(By.XPATH, '//button[text()="Companies"]')
        company_filter.click()
        soup = BeautifulSoup(driver.page_source)
        urns = []
        for elem in soup.findall('div', class_='entity-result'):
            urns.append(elem['data-chameleon-result-urn'])
        return urns

    #Now for beautiful soup.


'''
    grab list of companies
    for company in list
        grab url
    use fuzzywuzzy for picking the closest url aove 80%
    populate company linkedin data_from_url
'''
