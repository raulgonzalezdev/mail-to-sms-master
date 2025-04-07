# -*- coding: utf-8 -*-

import os
import flask
import requests

import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery
import json
import yagmail
import phonenumbers

# This variable specifies the name of a file that contains the OAuth 2.0
# information for this application, including its client_id and client_secret.
CLIENT_SECRETS_FILE = "client_secret.json"

# The OAuth 2.0 access scope allows for access to the
# authenticated user's account and requires requests to use an SSL connection.
SCOPES = ['https://www.googleapis.com/auth/drive.metadata.readonly',
          'https://www.googleapis.com/auth/calendar.readonly',
          'https://mail.google.com/']  # Añadido el scope de Gmail
API_SERVICE_NAME = 'drive'
API_VERSION = 'v2'

app = flask.Flask(__name__)
# Note: A secret key is included in the sample so that it works.
# If you use this code in your application, replace this with a truly secret
# key. See https://flask.palletsprojects.com/quickstart/#sessions.
app.secret_key = 'REPLACE ME - this value is here as a placeholder.'

@app.route('/')
def index():
  return print_index_table()

@app.route('/drive')
def drive_api_request():
  if 'credentials' not in flask.session:
    return flask.redirect('authorize')

  features = flask.session['features']

  if features['drive']:
    # Load credentials from the session.
    credentials = google.oauth2.credentials.Credentials(
        **flask.session['credentials'])

    drive = googleapiclient.discovery.build(
        API_SERVICE_NAME, API_VERSION, credentials=credentials)

    files = drive.files().list().execute()

    # Save credentials back to session in case access token was refreshed.
    # ACTION ITEM: In a production app, you likely want to save these
    #              credentials in a persistent database instead.
    flask.session['credentials'] = credentials_to_dict(credentials)

    return flask.jsonify(**files)
  else:
    # User didn't authorize read-only Drive activity permission.
    # Update UX and application accordingly
    return '<p>Drive feature is not enabled.</p>'

@app.route('/calendar')
def calendar_api_request():
  if 'credentials' not in flask.session:
    return flask.redirect('authorize')

  features = flask.session['features']

  if features['calendar']:
    # User authorized Calendar read permission.
    # Calling the APIs, etc.
    return ('<p>User granted the Google Calendar read permission. '+
            'This sample code does not include code to call Calendar</p>')
  else:
    # User didn't authorize Calendar read permission.
    # Update UX and application accordingly
    return '<p>Calendar feature is not enabled.</p>'

@app.route('/send_sms', methods=['GET', 'POST'])
def send_sms():
  if 'credentials' not in flask.session:
    return flask.redirect('authorize')

  features = flask.session['features']

  if not features.get('gmail', False):
    return '<p>Gmail feature is not enabled. You need to authorize Gmail access.</p>'

  if flask.request.method == 'POST':
    number = flask.request.form.get('phone_number')
    carrier = flask.request.form.get('carrier')
    message = flask.request.form.get('message')
    region = flask.request.form.get('region', 'US')
    is_mms = flask.request.form.get('is_mms') == 'on'

    # Cargar las credenciales desde la sesión
    credentials = google.oauth2.credentials.Credentials(
        **flask.session['credentials'])
    
    # Enviar el SMS usando MailToSMS con OAuth2
    result = send_mail_to_sms(number, carrier, message, credentials, 
                             region=region, mms=is_mms)
    
    # Guardar credenciales actualizadas en la sesión
    flask.session['credentials'] = credentials_to_dict(credentials)
    
    if result:
      return '<p>Mensaje enviado con éxito!</p><br>' + print_sms_form() + '<br>' + print_index_table()
    else:
      return '<p>Error al enviar el mensaje. Por favor, verifica los datos.</p><br>' + print_sms_form() + '<br>' + print_index_table()

  return print_sms_form() + '<br>' + print_index_table()

def send_mail_to_sms(number, carrier, message, credentials, region='US', mms=False):
  """
  Envía un SMS usando MailToSMS con credenciales OAuth2
  """
  try:
    # Validar el número de teléfono
    if not validate_number(number, region):
      return False

    # Obtener información de carriers
    gateway = get_sms_gateway(carrier, mms)
    if not gateway:
      return False

    # Construir la dirección de destino
    address = f"{number}@{gateway}"
    
    # Configurar yagmail con las credenciales OAuth2
    smtp_connection = yagmail.SMTP(
      user=credentials.client_id,
      oauth2_file=None,
      token={
        'access_token': credentials.token,
        'refresh_token': credentials.refresh_token
      }
    )
    
    # Enviar el mensaje
    smtp_connection.send(to=address, contents=message)
    return True
  except Exception as e:
    print(f"Error al enviar SMS: {e}")
    return False

def validate_number(number, region):
  """Valida un número de teléfono usando la biblioteca phonenumbers"""
  try:
    number = str(number).strip()
    parsed = phonenumbers.parse(number, region)
    return (phonenumbers.is_possible_number(parsed) and
            phonenumbers.is_valid_number(parsed))
  except Exception as e:
    print(f"Error validando número: {e}")
    return False

def get_sms_gateway(carrier, mms=False):
  """Obtiene el gateway SMS o MMS para un carrier específico"""
  try:
    # Cargar el archivo gateways.json
    gateways_file = os.path.join(os.path.dirname(__file__), "gateways.json")
    with open(gateways_file, "r") as fd:
      gateways = json.load(fd)["gateways"]
      
    # Buscar el carrier en los gateways
    for gateway in gateways:
      if carrier in gateway["carrier_names"]:
        if mms and "mms" in gateway:
          return gateway["mms"]
        elif "sms" in gateway:
          return gateway["sms"]
        elif "mms" in gateway:  # Fallback a MMS si no hay SMS
          return gateway["mms"]
    
    return None
  except Exception as e:
    print(f"Error obteniendo gateway: {e}")
    return None

def print_sms_form():
  """Genera un formulario HTML para enviar SMS"""
  try:
    # Cargar los carriers desde gateways.json
    gateways_file = os.path.join(os.path.dirname(__file__), "gateways.json")
    with open(gateways_file, "r") as fd:
      gateways = json.load(fd)["gateways"]
    
    # Generar opciones para el dropdown de carriers
    carrier_options = ""
    for gateway in gateways:
      carrier_name = gateway["carrier_names"][0]
      carrier_options += f'<option value="{carrier_name}">{carrier_name}</option>'
    
    # Generar el formulario HTML
    return f'''
      <h2>Enviar SMS</h2>
      <form method="post" action="/send_sms">
        <div>
          <label for="phone_number">Número de teléfono:</label>
          <input type="text" id="phone_number" name="phone_number" required>
        </div>
        <div>
          <label for="carrier">Operador:</label>
          <select id="carrier" name="carrier" required>
            {carrier_options}
          </select>
        </div>
        <div>
          <label for="message">Mensaje:</label>
          <textarea id="message" name="message" required></textarea>
        </div>
        <div>
          <label for="region">Región (código de país):</label>
          <input type="text" id="region" name="region" value="US">
        </div>
        <div>
          <label for="is_mms">
            <input type="checkbox" id="is_mms" name="is_mms">
            Enviar como MMS
          </label>
        </div>
        <button type="submit">Enviar SMS</button>
      </form>
    '''
  except Exception as e:
    print(f"Error generando formulario: {e}")
    return "<p>Error al generar el formulario SMS</p>"

@app.route('/authorize')
def authorize():
  # Create flow instance to manage the OAuth 2.0 Authorization Grant Flow steps.
  flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
      CLIENT_SECRETS_FILE, scopes=SCOPES)

  # The URI created here must exactly match one of the authorized redirect URIs
  # for the OAuth 2.0 client, which you configured in the API Console. If this
  # value doesn't match an authorized URI, you will get a 'redirect_uri_mismatch'
  # error.
  flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

  authorization_url, state = flow.authorization_url(
      # Enable offline access so that you can refresh an access token without
      # re-prompting the user for permission. Recommended for web server apps.
      access_type='offline',
      # Enable incremental authorization. Recommended as a best practice.
      include_granted_scopes='true')

  # Store the state so the callback can verify the auth server response.
  flask.session['state'] = state

  return flask.redirect(authorization_url)

@app.route('/oauth2callback')
def oauth2callback():
  # Specify the state when creating the flow in the callback so that it can
  # verified in the authorization server response.
  state = flask.session['state']

  flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
      CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
  flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

  # Use the authorization server's response to fetch the OAuth 2.0 tokens.
  authorization_response = flask.request.url
  flow.fetch_token(authorization_response=authorization_response)

  # Store credentials in the session.
  # ACTION ITEM: In a production app, you likely want to save these
  #              credentials in a persistent database instead.
  credentials = flow.credentials
  
  credentials = credentials_to_dict(credentials)
  flask.session['credentials'] = credentials

  # Check which scopes user granted
  features = check_granted_scopes(credentials)
  flask.session['features'] = features
  return flask.redirect('/')
  
@app.route('/revoke')
def revoke():
  if 'credentials' not in flask.session:
    return ('You need to <a href="/authorize">authorize</a> before ' +
            'testing the code to revoke credentials.')

  credentials = google.oauth2.credentials.Credentials(
    **flask.session['credentials'])

  revoke = requests.post('https://oauth2.googleapis.com/revoke',
      params={'token': credentials.token},
      headers = {'content-type': 'application/x-www-form-urlencoded'})

  status_code = getattr(revoke, 'status_code')
  if status_code == 200:
    return('Credentials successfully revoked.' + print_index_table())
  else:
    return('An error occurred.' + print_index_table())

@app.route('/clear')
def clear_credentials():
  if 'credentials' in flask.session:
    del flask.session['credentials']
  return ('Credentials have been cleared.<br><br>' +
          print_index_table())

def credentials_to_dict(credentials):
  return {'token': credentials.token,
          'refresh_token': credentials.refresh_token,
          'token_uri': credentials.token_uri,
          'client_id': credentials.client_id,
          'client_secret': credentials.client_secret,
          'granted_scopes': credentials.granted_scopes}

def check_granted_scopes(credentials):
  features = {}
  if 'https://www.googleapis.com/auth/drive.metadata.readonly' in credentials['granted_scopes']:
    features['drive'] = True
  else:
    features['drive'] = False

  if 'https://www.googleapis.com/auth/calendar.readonly' in credentials['granted_scopes']:
    features['calendar'] = True
  else:
    features['calendar'] = False
    
  if 'https://mail.google.com/' in credentials['granted_scopes']:
    features['gmail'] = True
  else:
    features['gmail'] = False

  return features

def print_index_table():
  return ('<table>' +
          '<tr><td><a href="/test">Test an API request</a></td>' +
          '<td>Submit an API request and see a formatted JSON response. ' +
          '    Go through the authorization flow if there are no stored ' +
          '    credentials for the user.</td></tr>' +
          '<tr><td><a href="/authorize">Test the auth flow directly</a></td>' +
          '<td>Go directly to the authorization flow. If there are stored ' +
          '    credentials, you still might not be prompted to reauthorize ' +
          '    the application.</td></tr>' +
          '<tr><td><a href="/send_sms">Enviar SMS</a></td>' +
          '<td>Envía un mensaje SMS utilizando tu cuenta de Gmail con OAuth2.</td></tr>' +
          '<tr><td><a href="/revoke">Revoke current credentials</a></td>' +
          '<td>Revoke the access token associated with the current user ' +
          '    session. After revoking credentials, if you go to the test ' +
          '    page, you should see an <code>invalid_grant</code> error.' +
          '</td></tr>' +
          '<tr><td><a href="/clear">Clear Flask session credentials</a></td>' +
          '<td>Clear the access token currently stored in the user session. ' +
          '    After clearing the token, if you <a href="/test">test the ' +
          '    API request</a> again, you should go back to the auth flow.' +
          '</td></tr></table>')

if __name__ == '__main__':
  # When running locally, disable OAuthlib's HTTPs verification.
  # ACTION ITEM for developers:
  #     When running in production *do not* leave this option enabled.
  os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

  # This disables the requested scopes and granted scopes check.
  # If users only grant partial request, the warning would not be thrown.
  os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'

  # Specify a hostname and port that are set as a valid redirect URI
  # for your API project in the Google API Console.
  app.run('localhost', 8080, debug=True)