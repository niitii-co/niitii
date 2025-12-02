from io import BytesIO
from threading import Thread
import json
import certifi
import logging
import pycurl

class CustomHandler(logging.Handler):
    def __init__(self, url, token, sender, recipient):
        super().__init__()
        self.url = url
        self.token = token
        self.sender = sender
        self.recipient = recipient

    def send_curl(self, data):
        headers = [
                "Accept: application/json",
                f"Authorization: Bearer {self.token}",
                "Content-Type: application/json"
        ]

        buffer = BytesIO()
        c = pycurl.Curl()
        c.setopt(pycurl.URL, self.url)
        c.setopt(pycurl.POST, 1)
        c.setopt(pycurl.HTTPHEADER, headers)
        c.setopt(pycurl.POSTFIELDS, data)
        c.setopt(pycurl.WRITEDATA, buffer)
        c.setopt(pycurl.CAINFO, certifi.where())

        c.perform()


    def emit(self, record):
        to_email = []
        for r in self.recipient:
            to_email.append({"to": [{"email": r}]})

        payload = f"{self.format(record)}"
        data = {
            "personalizations": to_email,
            "from": {"email": self.sender},
            "subject": "Error in app",
            "content": [{
                "type": "text/plain", "value": payload
                }]
        }

        args = json.dumps(data)
# To prevent Thread from unpacking arguments, you must wrap your sequence (like a list or tuple) within another tuple so it is treated as a single object
# Wrap the list in a single-item tuple using a trailing comma.
        Thread(target=self.send_curl, args=(args,)).start()



