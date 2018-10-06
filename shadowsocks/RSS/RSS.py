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

#解码订阅内容获得配置保存在目录config
def save_config(url):

    data=get_data(url)
    ssr_str=ssr_decode.decode(data)

    code_list = re.findall("ssr://(\w+)", ssr_str)

    for code in code_list:
        index = code_list.index(code)
        try:
            ssr_decode.save_as_json(code,name=str(index))
        except UnicodeDecodeError:
            print(ssr_decode.decode(code))  #打印有误的链接

if __name__ == '__main__':
    url = input("ssr subscrible link:")
    save_config(url)
    print("successful!")
