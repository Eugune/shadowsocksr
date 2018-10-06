import base64
import re
import json

ssr = ""
code = ssr[6:]

def Analyze(s):

    config = {
        "server": "0.0.0.0",
        "server_ipv6": "::",
        "server_port": 8388,
        "local_address": "127.0.0.1",
        "local_port": 1080,

        "password": "m",
        "method": "aes-128-ctr",
        "protocol": "auth_aes128_md5",
        "protocol_param": "",
        "obfs": "tls1.2_ticket_auth_compatible",
        "obfs_param": ""
    }

    s = decode(s)
    spilted = re.split(':', s)
    pass_param = spilted[5]
    pass_param_spilted = re.split("\/\?", pass_param)
    passwd = decode(pass_param_spilted[0])
    param_patern = re.compile(r'obfsparam=(\w+)|protoparam=(\w+)|remarks=([^&]+)|group=(.+)')
    param_result = re.findall(param_patern, pass_param_spilted[1])
    obfs_param = decode(param_result[0][0])
    protocol_param = decode(param_result[1][1])
    remarks = decode(param_result[2][2])
    group = decode(param_result[3][3])
    
    config['server'] = spilted[0]
    config['server_port'] = int(spilted[1])
    config['password'] = passwd
    config['method'] = spilted[3]
    config['protocol'] = spilted[2]
    config['obfs'] = spilted[4]
    config['protocol_param'] = protocol_param
    config['obfs_param'] = obfs_param

    return config
    
#因为base64解码的永远是4的倍数所以我们需要在最后添加'='构成四的倍数完成解码
def decode(s):

    count = len(s)
    num = 4-count%4
    if count%4==0:
        s = base64.urlsafe_b64decode(s)
    else:
        s = s + num*"="
        s = base64.urlsafe_b64decode(s)
    
    s = str(s,encoding="utf-8")
    return s

def save_as_json(d):
    
    data_dict = Analyze(d)
    json_str = json.dumps(data_dict)
    with open('config/test.json','w') as f:
        json.dump(data_dict, f)

if __name__ == "__main__":
    save_as_json(code)

