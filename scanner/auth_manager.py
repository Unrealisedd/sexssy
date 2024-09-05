import yaml
import requests

class AuthManager:
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        self.auth_config = None
        self.session = requests.Session()

    def load_auth_config(self, auth_config_file):
        with open(auth_config_file, 'r') as f:
            self.auth_config = yaml.safe_load(f)

    def authenticate(self, url):
        if not self.auth_config:
            return

        auth_type = self.auth_config.get('type', 'form')
        if auth_type == 'form':
            self._form_authentication(url)
        elif auth_type == 'basic':
            self._basic_authentication()
        elif auth_type == 'token':
            self._token_authentication()
        else:
            self.logger.error(f"Unsupported authentication type: {auth_type}")

    def _form_authentication(self, url):
        login_url = self.auth_config.get('login_url', url)
        username = self.auth_config.get('username')
        password = self.auth_config.get('password')
        username_field = self.auth_config.get('username_field', 'username')
        password_field = self.auth_config.get('password_field', 'password')

        data = {
            username_field: username,
            password_field: password
        }

        response = self.session.post(login_url, data=data)
        if response.status_code == 200:
            self.logger.info("Form authentication successful")
        else:
            self.logger.error("Form authentication failed")

    def _basic_authentication(self):
        username = self.auth_config.get('username')
        password = self.auth_config.get('password')
        self.session.auth = (username, password)
        self.logger.info("Basic authentication configured")

    def _token_authentication(self):
        token = self.auth_config.get('token')
        token_type = self.auth_config.get('token_type', 'Bearer')
        self.session.headers['Authorization'] = f"{token_type} {token}"
        self.logger.info("Token authentication configured")

    def get_session(self):
        return self.session
