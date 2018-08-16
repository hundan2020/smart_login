# coding=utf-8
import binascii
import rsa
from urllib import request
import json
from urllib import parse
from time import time
from base64 import b64encode


def sina_login(username, password):
    """
    it will return a json like this
    {'crossDomainUrlList': ['https://passport.weibo.com/wbsso/login?ticket=xxxxxxxxxxx', 'https://passport.97973.com/sso/crossdomai
    n?action=login&savestate=xxxxxx', 'https://passport.weibo.cn/sso/crossdomain?action=login&savestate=1'], 'retcode': '0', 'nick': 'your nick name', 'uid': 'your uid'}
    retcode: 0 means login success
    :param username: your username/phone/email
    :param password: your password
    :return:sina login json
    """
    headers={
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.106 Safari/537.36",
        "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
        "Referer":"http://my.sina.com.cn/profile/logined",
        # "Accept-Encoding":"gzip, deflate",
        "Accept-Language":"zh-CN,zh;q=0.9,en;q=0.8",
        # "Cookie": "U_TRS1=00000084.9bed62e5.5b72e391.3af21d2e; SCF=AjEDrkrhvxII4wJgdIV9siNQUgJlzg1gCS6LX_Ez6o0W1cSlWagP_ThVB_NwZOFToQvMbCX9hsIs2AxCepx3Sl4.; SINAGLOBAL=172.16.118.83_1534345349.885837; Apache=172.16.118.83_1534345349.885840; SSO-DBL=1d143a736fdf93d35dc1b24d4482f559; U_TRS2=00000019.45af8203.5b7454e9.728b1791; UOR=my.sina.com.cn,www.sina.com.cn,; ULV=1534350579211:1:1:1:172.16.118.83_1534345349.885840:; SGUID=1534350580654_19785330; SUBP=0033WrSXqPxfM72wWs9jqgMF55529P9D9WWKg4cDuqqTVV3F8DJe0slF5JpV2sSQ9g8Xeg4rBh2ceE4odcXt; lxlrttp=1532434326; SUB=_2AkMsKNvLdcPxrAVQnfodxG3iZIlH-jyf_bI9An7tJhMyAhh87gcGqSVutBF-XLPEJgbxOuOj0nCYCFiZeP8D0XI0"
    }

    q = {
        "entry": "account",
        "_": int(time()*1000),
        "callback": "pluginSSOController.preloginCallBack",
        "su": b64encode(username.encode("utf-8")),
        "rsakt": "mod",
        "checkpin": "1",
        "client": "ssologin.js(v1.4.19)",
    }
    eq = parse.urlencode(q).encode("utf-8")
    u = request.Request("https://login.sina.com.cn/sso/prelogin.php?" + eq.decode("utf-8"), headers=headers, method="GET")
    r = request.urlopen(u)
    rb = r.read()
    b = json.loads(rb.decode("utf-8")[37:-1])
    pkey = rsa.PublicKey(int(b['pubkey'], 16), 65537)
    msg = str(b['servertime']) + "\t" + b["nonce"] + "\n" + password
    rmsg = rsa.encrypt(msg.encode("utf-8"), pkey)
    sp = binascii.b2a_hex(rmsg)
    data = {
        "entry": "account",
        "gateway": "1",
        "from": "",
        "savestate": "30",
        "qrcode_flag": "true",
        "useticket": "0",
        "pagerefer": "http://my.sina.com.cn/profile/logined",
        "vsnf": "1",
        "su": b64encode(username.encode("utf-8")),
        "sp": sp,
        "service": "sso",
        "servertime": b["servertime"],
        "nonce": b["nonce"],
        "pwencode": "rsa2",
        "rsakv": b["rsakv"],
        "sr": "1366*768",
        "encoding": "UTF-8",
        "cdult": "3",
        "domain": "sina.com.cn",
        "prelt": "68",
        "returntype": "TEXT",
        }
    edata = parse.urlencode(data).encode("utf-8")
    u = request.Request("https://login.sina.com.cn/sso/login.php?client=ssologin.js(v1.4.19)&_=" + str(time() * 1000), data=edata, headers=headers, method="POST")
    r = request.urlopen(u)
    dr = r.read().decode("utf-8")
    jr = json.loads(dr)
    return jr

result = sina_login(username='yourname/phone/email', password='yourpassword')
print(result)
