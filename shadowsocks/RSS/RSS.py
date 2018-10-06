import ssr_decode
import re
from urllib import request

url = ""

def get_data(url):
    header = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36'}
    req = request.Request(url,headers=header)
    with request.urlopen(req) as res:
        data = str(res.read(),encoding="utf-8")
        return data

data=get_data(url)
ssr_str=ssr_decode.decode(data)

code = re.findall("ssr://(\w+)", ssr_str)
print(code[0])
first = ssr_decode.Analyze(code[15])
print(first)
