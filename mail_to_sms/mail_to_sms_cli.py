from __future__ import print_function

from mail_to_sms import MailToSMS
import os
import click


## See MailToSMS docstring for information about the arguments
@click.command()
@click.argument("phone-number", type=str)
@click.argument("carrier", type=str)
@click.argument("message", type=str)
@click.option("--yagmail-username", "-u", type=str, help="Specify a specific username for the SMTP server (ex. 'username'). Not necessary if a yagmail keyring and a .yagmail file are in use.")
@click.option("--yagmail-password", "-p", type=str, help="Specify a specific password for the SMTP server (ex. 'password'). Not necessary if a yagmail keyring and a .yagmail file are in use.")
@click.option("--oauth2", is_flag=True, help="Use OAuth2 authentication instead of username/password.")
@click.option("--client-secrets-file", type=str, default="client_secret.json", help="Path to client_secret.json file for OAuth2 authentication. Defaults to 'client_secret.json'.")
@click.option("--region", type=str, default="US", help="The region of the destination phone number. Defaults to 'US' (ex. 'VE' for Venezuela).")
@click.option("--mms", is_flag=True, help="Choose to send a MMS message instead of a SMS message. Will fallback to SMS if MMS isn't available.")
@click.option("--subject", type=str, help="The subject of the email to send (ex. 'This is a subject').")
@click.option("--quiet", is_flag=True, help="Disable printed statements.")
def main(phone_number, carrier, message, yagmail_username, yagmail_password, oauth2, client_secrets_file, region, mms, subject, quiet):
    """
    Send an SMS message through email using MailToSMS.
    
    Example with username/password:
    mail_to_sms_cli 5551234567 att "This is a test message" -u username@gmail.com -p password
    
    Example with OAuth2:
    mail_to_sms_cli 5551234567 att "This is a test message" --oauth2 --client-secrets-file=client_secret.json
    """
    kwargs = {
        "region": region,
        "mms": mms,
        "quiet": quiet
    }
    
    if subject:
        kwargs["subject"] = subject
    
    if oauth2:
        # Use OAuth2 authentication
        if not os.path.exists(client_secrets_file):
            click.echo(f"Error: OAuth2 client secrets file not found: {client_secrets_file}")
            return
        
        kwargs["oauth2"] = True
        kwargs["client_secrets_file"] = client_secrets_file
        
        MailToSMS(phone_number, carrier, contents=message, **kwargs)
    else:
        # Use traditional username/password authentication
        MailToSMS(phone_number, carrier, yagmail_username, yagmail_password, message, **kwargs)

if(__name__ == "__main__"):
    main()