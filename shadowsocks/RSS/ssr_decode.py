import base64
import re
import json

ssr = "ssr://"
code = ssr[6:]
name = 'config'

#解析我们的ssr code 返回一个有config,group,remarks组成的列表,其中config为dict，其余两个为string
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

    #匹配param、remark和group 
    try:
        obfs_param = re.search(r'obfsparam=([^&]+)', pass_param_spilted[1]).group(1)
        obfs_param = decode(obfs_param)
    except:
        obfs_param = ''
    try:
        protocol_param = re.search(r'protoparam=([^&]+)', pass_param_spilted[1])
        protocol_param = decode(protocol_param)
    except:
        protocol_param = ''
    try:
        remarks = re.search(r'remarks=([^&]+)', pass_param_spilted[1]).group(1)
        remarks = decode(remarks)
    except:
        remarks = ''
    try:
        group = re.search(r'group=([^&]+)', pass_param_spilted[1]).group(1)
        group = decode(group)
    except:
        group = ''

    config['server'] = spilted[0]
    config['server_port'] = int(spilted[1])
    config['password'] = passwd
    config['method'] = spilted[3]
    config['protocol'] = spilted[2]
    config['obfs'] = spilted[4]
    config['protocol_param'] = protocol_param
    config['obfs_param'] = obfs_param
    
    return [config,group,remarks]
    
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

def save_as_json(d,name='conf'):
    
    [data_dict,group,remarks] = Analyze(d)
    json_str = json.dumps(data_dict)
    with open('config/'+name+'.json','w') as f:
        json.dump(data_dict, f)

if __name__ == "__main__":
    ssr = input('ssr link:')
    code = ssr[6:]
    name = input('config name:')
    save_as_json(code,name)

