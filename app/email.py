from app import mail
from flask import current_app, json
from flask_mail import Message
from io import BytesIO
from threading import Thread
import certifi
import pycurl


def send_async_email(app, msg):
    with app.app_context():
        mail.send(msg)


def send_curl_email(app, json_payload):
    with app.app_context():
        API_URL = current_app.config['MAIL_API_URL']
        API_TOKEN = current_app.config['MAIL_PASSWORD']
        
        headers = [
            "Accept: application/json",
            f"Authorization: Bearer {API_TOKEN}",
            "Content-Type: application/json"
        ]

        buffer = BytesIO()
        c = pycurl.Curl()
        c.setopt(pycurl.URL, API_URL)
        c.setopt(pycurl.POST, 1)
        c.setopt(pycurl.HTTPHEADER, headers)
        c.setopt(pycurl.POSTFIELDS, json_payload)
        c.setopt(pycurl.WRITEDATA, buffer)
        c.setopt(pycurl.CAINFO, certifi.where())        

        c.perform()

#        try:
#            c.perform()

#            # Get the HTTP status code. Returns type 'int'
#            status_code = c.getinfo(pycurl.RESPONSE_CODE)

#            # Decode and print the API response
#            response_body = buffer.getvalue().decode('utf-8')

#            if not status_code < 300:
#                print(f"API Response Status: {status_code}")
#            if not response_body == '':
#                print(f"API Response Body: {response_body}")

#        except pycurl.error as e:
#            print(f"Thread {thread_id} error: {e}")

#        finally:
#            c.close()


def send_email(subject, sender, recipient, text_body, html_body, attachments=None, sync=False, **kwargs):
#    Send via SMTP
#    msg = Message(subject, sender=sender, recipient=recipient)
#    msg.body = text_body
#    msg.html = html_body
#    # attach() accepts 3 args. filename, media type, actual file data. filename is what recipient sees attached.
#    if attachments:
#        for attachment in attachments:
#            msg.attach(*attachment)
#    if sync:
#        mail.send(msg)
#    else:
#        Thread(target=send_async_email,
#               args=(current_app._get_current_object(), msg)).start()

#    Send via curl
    to_email = []
    for r in recipient:
        to_email.append({"to": [{"email": r}]})

    data = {
        "personalizations": to_email,
        "from": {"email": sender},
        "subject": subject,
        "content": [{
            "type": "text/plain", "value": text_body
            }]
    }
    json_payload = json.dumps(data)

    Thread(target=send_curl_email, args=(current_app._get_current_object(), json_payload)).start()




