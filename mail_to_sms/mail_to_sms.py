from __future__ import print_function

import json
import os

import yagmail
import phonenumbers
import google.oauth2.credentials
import google_auth_oauthlib.flow


class MailToSMS:
    """MailToSMS

    This module implements a basic api for sending text messages via email using yagmail.

    Arguments:
        number {string|int}: The destination phone number (ex. 5551234567)
        carrier {string}: The destination phone number's carrier (ex. "att")
        username {string} [optional]: The username for accessing the SMTP server (ex. "username").
            If omitted, it'll try to use the username stored in the .yagmail file.
            See: https://github.com/kootenpv/yagmail#username-and-password
        password {string} [optional]: The password for accessing the SMTP server (ex. "password").
            If using Gmail and 2FA, you may want to use an app password.
            If omitted, it'll try to use yagmail's password in the keyring, otherwise it'll prompt you for the password.
            See: https://github.com/kootenpv/yagmail#username-and-password
        contents {yagmail contents} [optional]: A yagmail friendly contents argument (ex. "This is a message."). 
            See: https://github.com/kootenpv/yagmail#magical-contents
            If omitted, you can manually use MailToSMS's send method.
        keyworded args (for extra configuration):
            quiet {boolean}: Choose to disable printed statements. Defaults to False. (ex. quiet=True)
            region {string}: The region of the destination phone number. Defaults to "US". (ex. region="US")
                This should only be necessary when using a non international phone number that's not US based.
                See: https://github.com/daviddrysdale/python-phonenumbers
            mms {boolean}: Choose to send a MMS message instead of a SMS message, but will fallback to SMS if MMS isn't present. Defaults to False. (ex. mms=True)
            subject {string}: The subject of the email to send (ex. subject="This is a subject.")
            yagmail {list}: A list of arguments to send to the yagmail.SMTP() constructor. (ex. yagmail=["my.smtp.server.com", "12345"])
                As of 4/30/17, the args and their defaults (after the username and password) are:
                    host='smtp.gmail.com', port='587', smtp_starttls=True, smtp_set_debuglevel=0, smtp_skip_login=False, encoding="utf-8"
                This is unnecessary if you're planning on using the basic Gmail interface, 
                    in which case you'll just need the username and password.
                See: https://github.com/kootenpv/yagmail/blob/master/yagmail/yagmail.py#L49
            oauth2 {boolean}: Set to True to use OAuth2 authentication. Defaults to False. (ex. oauth2=True)
            client_secrets_file {string}: Path to client_secret.json file for OAuth2. (ex. client_secrets_file="client_secret.json")
            credentials {google.oauth2.credentials.Credentials}: OAuth2 credentials. If provided, client_secrets_file is ignored.
            token {dict}: OAuth2 token containing access_token and refresh_token. Used with oauth2=True.

    Examples:
        from mail_to_sms import MailToSMS

        # Using traditional username/password:
        MailToSMS(5551234567, "att", "username@gmail.com", "password", "this is a message")

        # Using OAuth2 with client_secret.json:
        MailToSMS(5551234567, "att", contents="this is a message", oauth2=True, client_secrets_file="client_secret.json")

        # Using OAuth2 with existing credentials:
        MailToSMS(5551234567, "att", contents="this is a message", oauth2=True, credentials=my_credentials)

        # Using OAuth2 with token:
        token = {'access_token': 'ya29.abc123', 'refresh_token': '1//xyzABC...'}
        MailToSMS(5551234567, "att", contents="this is a message", oauth2=True, token=token)

    Requirements:
        yagmail
        phonenumbers
        google-auth-oauthlib
        click (for the CLI)
    """

    ## Config
    GATEWAYS_JSON_PATH = os.path.join(os.path.dirname(__file__), "gateways.json")
    GATEWAYS_KEY = "gateways"
    CARRIER_NAMES_KEY = "carrier_names"
    SMS_KEY = "sms"
    MMS_KEY = "mms"
    QUIET_KEY = "quiet"
    REGION_KEY = "region"
    SUBJECT_KEY = "subject"
    YAGMAIL_KEY = "yagmail"
    OAUTH2_KEY = "oauth2"
    CLIENT_SECRETS_FILE_KEY = "client_secrets_file"
    CREDENTIALS_KEY = "credentials"
    TOKEN_KEY = "token"
    DEFAULT_CLIENT_SECRETS_FILE = "client_secret.json"
    SCOPES = ['https://mail.google.com/']

    ## Defaults
    DEFAULT_QUIET = False
    DEFAULT_TO_MMS = False
    DEFAULT_REGION = "US"
    DEFAULT_SUBJECT = None
    DEFAULT_YAGMAIL_ARGS = []
    DEFAULT_OAUTH2 = False


    def __init__(self, number, carrier, username=None, password=None, contents=None, **kwargs):
        ## Explicitly define the available configs and their defaults (if necessary)
        self.config = {
            "quiet": kwargs.get(self.QUIET_KEY, self.DEFAULT_QUIET),
            "region": kwargs.get(self.REGION_KEY, self.DEFAULT_REGION),
            "subject": kwargs.get(self.SUBJECT_KEY, self.DEFAULT_SUBJECT),
            "mms": kwargs.get(self.MMS_KEY, self.DEFAULT_TO_MMS),
            "yagmail": kwargs.get(self.YAGMAIL_KEY, self.DEFAULT_YAGMAIL_ARGS),
            "oauth2": kwargs.get(self.OAUTH2_KEY, self.DEFAULT_OAUTH2),
            "client_secrets_file": kwargs.get(self.CLIENT_SECRETS_FILE_KEY, self.DEFAULT_CLIENT_SECRETS_FILE),
            "credentials": kwargs.get(self.CREDENTIALS_KEY, None),
            "token": kwargs.get(self.TOKEN_KEY, None)
        }

        ## Prepare the address to send to, return if it couldn't be generated
        self.address = self._build_address(number, carrier)
        if(not self.address):
            return

        ## Init the yagmail connection
        try:
            if self.config.get("oauth2"):
                # Usar autenticación OAuth2
                self.connection = self._init_oauth2_connection(username)
            else:
                # Usar autenticación tradicional con usuario/contraseña
                yagmail_args = self.config["yagmail"]
                if(username):
                    yagmail_args.insert(0, username)
                    yagmail_args.insert(1, password)
                self.connection = yagmail.SMTP(*yagmail_args)
        except Exception as e:
            ## You might want to look into using an app password for this.
            self._print_error(e, "Unhandled error creating yagmail connection.")
            return

        ## Send the mail if the contents arg has been provided, otherwise
        ## the send() method can be called manually.
        if(contents):
            self.send(contents)

    ## Methods

    def _init_oauth2_connection(self, username=None):
        """
        Inicializa una conexión yagmail usando autenticación OAuth2
        """
        credentials = self.config.get("credentials")
        token = self.config.get("token")
        client_secrets_file = self.config.get("client_secrets_file")
        
        if not credentials and not token and not os.path.exists(client_secrets_file):
            self._print_error(None, f"OAuth2 file not found: {client_secrets_file}")
            return None
            
        try:
            # Si no tenemos credenciales pero tenemos el token
            if not credentials and token:
                # Si username no está definido, intenta obtenerlo del client_secrets_file
                if not username and os.path.exists(client_secrets_file):
                    with open(client_secrets_file, 'r') as f:
                        client_info = json.load(f)
                        if 'web' in client_info:
                            client_id = client_info['web'].get('client_id')
                            if client_id:
                                username = client_id
                
                # Crear la conexión usando el token proporcionado
                return yagmail.SMTP(
                    user=username,
                    oauth2_file=None,
                    token=token
                )
            
            # Si tenemos las credenciales directamente
            elif credentials:
                token_info = {
                    'access_token': credentials.token,
                    'refresh_token': credentials.refresh_token
                }
                
                return yagmail.SMTP(
                    user=credentials.client_id,
                    oauth2_file=None,
                    token=token_info
                )
            
            # Si tenemos que cargar las credenciales desde client_secrets_file
            else:
                # Crear el flujo OAuth2 desde el archivo de secretos
                flow = google_auth_oauthlib.flow.InstalledAppFlow.from_client_secrets_file(
                    client_secrets_file, self.SCOPES)
                credentials = flow.run_local_server(port=0)
                
                # Crear la conexión usando las credenciales obtenidas
                token_info = {
                    'access_token': credentials.token,
                    'refresh_token': credentials.refresh_token
                }
                
                return yagmail.SMTP(
                    user=credentials.client_id,
                    oauth2_file=None,
                    token=token_info
                )
        except Exception as e:
            self._print_error(e, "Error initializing OAuth2 connection")
            return None

    def _print_error(self, exception, message=None):
        output = []
        if(exception):
            output.append(str(exception))
        if(message):
            output.append(str(message))

        if(output):
            joined = " ".join(output)
            ## Inefficient logic to aid in testing
            if(not self.config["quiet"]):
                print(joined)
            return joined
        else:
            return None


    def _load_gateways(self):
        with open(self.GATEWAYS_JSON_PATH, "r") as fd:
            try:
                return json.load(fd)[self.GATEWAYS_KEY]
            except Exception as e:
                self._print_error(e, "Unhandled error loading gateways.json.")
                return []


    def _validate_number(self, number, region):
        number = str(number).strip()

        try:
            parsed = phonenumbers.parse(number, region)
        except phonenumbers.phonenumberutil.NumberParseException as e:
            self._print_error(e, "NumberParseException when parsing the phone number.")
            return False
        except Exception as e:
            self._print_error(e, "Unhandled error when parsing the phone number.")
            return False

        else:
            if (phonenumbers.is_possible_number(parsed) and
                phonenumbers.is_valid_number(parsed)):
                return True
            else:
                self._print_error(None, "'{0}' isn't a valid phone number".format(number))
                return False


    def _validate_carrier(self, carrier):
        carrier = str(carrier).strip()

        for gateway in self.gateways:
            if(carrier in gateway[self.CARRIER_NAMES_KEY]):
                return True
        else:
            self._print_error(None, "'{0}' isn't a valid carrier.".format(carrier))
            return False


    def _get_gateway(self, carrier):
        for gateway in self.gateways:
            if(carrier in gateway[self.CARRIER_NAMES_KEY]):
                if(self.config.get(self.MMS_KEY)):
                    ## Return mms gateway if possible, else return the sms gateway
                    if(self.MMS_KEY in gateway):
                        return gateway[self.MMS_KEY]
                    elif(self.SMS_KEY in gateway):
                        return gateway[self.SMS_KEY]
                else:
                    ## Return sms gateway if possible, else return the mms gateway
                    if(self.SMS_KEY in gateway):
                        return gateway[self.SMS_KEY]
                    elif(self.MMS_KEY in gateway):
                        return gateway[self.MMS_KEY]
        else:
            ## This shouldn't happen.
            self._print_error(None, "Carrier '{0}' doesn't have any valid SMS or MMS gateways.".format(carrier))
            return None


    def _build_address(self, number, carrier):
        ## Load and ensure that there are gateways to check
        self.gateways = self._load_gateways()
        if(not self.gateways):
            return None

        ## Validate the phone number and carrier
        if (not self._validate_number(number, self.config["region"]) or
            not self._validate_carrier(carrier)):
            return None

        ## Get the SMS/MMS gateway for the carrier
        gateway = self._get_gateway(carrier)
        if(not gateway):
            return None

        return "{0}@{1}".format(number, gateway)


    def send(self, contents):
        ## Prepare kwargs for yagmail.send()
        yagmail_kwargs = {
            "to": self.address,
            "subject": self.config["subject"],
            "contents": contents
        }

        ## Send the mail
        try:
            self.connection.send(**yagmail_kwargs)
        except Exception as e:
            self._print_error(e, "Unhandled error sending mail.")
            return False
        else:
            return True
