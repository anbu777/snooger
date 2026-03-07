import requests
import pickle
import os
import re
from urllib.parse import urlparse

class AuthManager:
    def __init__(self, workspace_dir):
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0'})
        self.base_url = None
        self.logged_in = False
        self.workspace_dir = workspace_dir
        self.auth_type = None
        self.auth_data = {}
        self.session_file = os.path.join(workspace_dir, 'auth_session.pkl')

    def set_base_url(self, url):
        self.base_url = url.rstrip('/')

    def load_session(self):
        if os.path.exists(self.session_file):
            try:
                with open(self.session_file, 'rb') as f:
                    self.session.cookies.update(pickle.load(f))
                self.logged_in = True
                return True
            except Exception:
                pass
        return False

    def save_session(self):
        with open(self.session_file, 'wb') as f:
            pickle.dump(self.session.cookies, f)

    def export_cookies_netscape(self, filepath):
        with open(filepath, 'w') as f:
            f.write("# Netscape HTTP Cookie File\n")
            for cookie in self.session.cookies:
                domain = cookie.domain
                flag = "TRUE" if domain.startswith('.') else "FALSE"
                path = cookie.path
                secure = "TRUE" if cookie.secure else "FALSE"
                expiry = str(int(cookie.expires)) if cookie.expires else "0"
                name = cookie.name
                value = cookie.value
                f.write(f"{domain}\t{flag}\t{path}\t{secure}\t{expiry}\t{name}\t{value}\n")

    def login_form(self, login_url, username, password, username_field='username', password_field='password', extra_data=None, csrf_field=None):
        print(f"[Auth] Attempting form login to {login_url}")
        self.auth_type = 'form'
        self.auth_data = {'username': username, 'password': password}
        data = {username_field: username, password_field: password}
        if extra_data:
            data.update(extra_data)
        if csrf_field:
            try:
                resp = self.session.get(login_url)
                match = re.search(r'name=["\']?{}["\']?\s+value=["\']?([^"\'>]+)'.format(csrf_field), resp.text, re.I)
                if match:
                    data[csrf_field] = match.group(1)
                else:
                    print("[Auth] Could not find CSRF token automatically")
            except Exception as e:
                print(f"[Auth] Error fetching CSRF: {e}")
        try:
            resp = self.session.post(login_url, data=data, allow_redirects=True)
            if resp.status_code == 200:
                if any(x in resp.text.lower() for x in ['logout', 'dashboard', 'profile', 'welcome']):
                    self.logged_in = True
                    print("[Auth] Login successful")
                    self.save_session()
                    return True
                else:
                    print("[Auth] Login may have failed (no typical success indicators)")
                    return False
            else:
                print(f"[Auth] Login failed with status {resp.status_code}")
                return False
        except Exception as e:
            print(f"[Auth] Login error: {e}")
            return False

    def login_basic(self, username, password):
        from requests.auth import HTTPBasicAuth
        self.auth_type = 'basic'
        self.auth_data = {'username': username, 'password': password}
        self.session.auth = HTTPBasicAuth(username, password)
        self.logged_in = True
        print("[Auth] Basic auth set")
        return True

    def set_token(self, token, header='Authorization', scheme='Bearer'):
        self.auth_type = 'token'
        self.auth_data = {'token': token, 'header': header, 'scheme': scheme}
        self.session.headers.update({header: f'{scheme} {token}'})
        self.logged_in = True
        print("[Auth] Token set")
        return True

    def set_cookies(self, cookies_dict):
        self.auth_type = 'cookies'
        self.auth_data = cookies_dict
        self.session.cookies.update(cookies_dict)
        self.logged_in = True
        print("[Auth] Cookies set")
        return True

    def request(self, method, url, **kwargs):
        if not self.base_url:
            full_url = url
        else:
            if url.startswith('http'):
                full_url = url
            else:
                full_url = self.base_url + url
        return self.session.request(method, full_url, **kwargs)

    def get(self, url, **kwargs):
        return self.request('GET', url, **kwargs)

    def post(self, url, **kwargs):
        return self.request('POST', url, **kwargs)

    def is_logged_in(self):
        return self.logged_in

    def logout(self):
        self.session.cookies.clear()
        self.session.auth = None
        self.logged_in = False
        if os.path.exists(self.session_file):
            os.remove(self.session_file)
        print("[Auth] Logged out")