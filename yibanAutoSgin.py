# -*- coding: utf-8 -*-
import requests
import json
import re
import time
import base64
import smtplib
from email.mime.text import MIMEText
from email.utils import formataddr
import os
import sys

try:
    import requests
except ModuleNotFoundError:
    print("缺少requests依赖,安装依赖")
    os.system("pip3 install requests -i https://pypi.tuna.tsinghua.edu.cn/simple")
    os.execl(sys.executable, 'python3', __file__, *sys.argv)

try:
    from Crypto.Cipher import PKCS1_v1_5
    from Crypto.PublicKey import RSA
except ModuleNotFoundError:
    print("缺少pycryptodome依赖,安装依赖")
    os.system("pip3 install pycryptodome -i https://pypi.tuna.tsinghua.edu.cn/simple")
    os.execl(sys.executable, 'python3', __file__, *sys.argv)

def encryptPassword(pwd):
    # 密码加密
        PUBLIC_KEY = '''-----BEGIN PUBLIC KEY-----
            MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA6aTDM8BhCS8O0wlx2KzA
            Ajffez4G4A/QSnn1ZDuvLRbKBHm0vVBtBhD03QUnnHXvqigsOOwr4onUeNljegIC
            XC9h5exLFidQVB58MBjItMA81YVlZKBY9zth1neHeRTWlFTCx+WasvbS0HuYpF8+
            KPl7LJPjtI4XAAOLBntQGnPwCX2Ff/LgwqkZbOrHHkN444iLmViCXxNUDUMUR9bP
            A9/I5kwfyZ/mM5m8+IPhSXZ0f2uw1WLov1P4aeKkaaKCf5eL3n7/2vgq7kw2qSmR
            AGBZzW45PsjOEvygXFOy2n7AXL9nHogDiMdbe4aY2VT70sl0ccc4uvVOvVBMinOp
            d2rEpX0/8YE0dRXxukrM7i+r6lWy1lSKbP+0tQxQHNa/Cjg5W3uU+W9YmNUFc1w/
            7QT4SZrnRBEo++Xf9D3YNaOCFZXhy63IpY4eTQCJFQcXdnRbTXEdC3CtWNd7SV/h
            mfJYekb3GEV+10xLOvpe/+tCTeCDpFDJP6UuzLXBBADL2oV3D56hYlOlscjBokNU
            AYYlWgfwA91NjDsWW9mwapm/eLs4FNyH0JcMFTWH9dnl8B7PCUra/Lg/IVv6HkFE
            uCL7hVXGMbw2BZuCIC2VG1ZQ6QD64X8g5zL+HDsusQDbEJV2ZtojalTIjpxMksbR
            ZRsH+P3+NNOZOEwUdjJUAx8CAwEAAQ==
            -----END PUBLIC KEY-----'''
        cipher = PKCS1_v1_5.new(RSA.importKey(PUBLIC_KEY))
        cipher_text = base64.b64encode(cipher.encrypt(bytes(pwd, encoding="utf8")))
        return cipher_text.decode("utf-8")

def sendEmail():
        #邮箱服务器地址
        host_server = 'smtp.office365.com'
        #发送者邮件地址
        from_email = '#####'
        #接收者的邮件地址
        to_email = '####'
        #邮件密码
        password = '#####'
        #获取当前的时间
        now_time = time.strftime("%Y-%m-%d %H:%M:%S",time.localtime(time.time()))
        text_msg = now_time + '签到成功了！'
        msg = MIMEText(text_msg, 'plain', 'utf-8')
        msg["Accept-Language"] = "zh-CN"
        msg["Accept-Charset"] = "ISO-8859-1,utf-8"
        # 发件人邮箱昵称、发件人邮箱账号
        msg['From'] = formataddr(["发件人昵称", from_email])
         # 收件人邮箱昵称、收件人邮箱账号
        msg['To'] = formataddr(["收件人昵称", to_email])
        msg['Subject'] = "邮件主题"
        smtp_server = smtplib.SMTP(host_server,587)
        smtp_server.ehlo()
        smtp_server.starttls()
        smtp_server.login(from_email,password)
        smtp_server.sendmail(from_email,to_email,msg.as_string())
        smtp_server.quit()
        print(now_time + " 邮件发送成功")



class yiban:
    CSRF = "38717fe231a62f75253f9529f9e778d5"
    COOKIES = {"csrf_token": CSRF}
    HEADERS = {"Origin": "'https://m.yiban.cn", 'AppVersion': '5.0.1', "User-Agent": "YiBan/5.0.1"}

    
    def __init__(self, mobile, password):
        self.mobile = mobile
        self.password = password
        self.session = requests.session()
        # 从https://lbs.amap.com/tools/picker 寻找宿舍经纬度
        # https://apecodewx.gitee.io/sixuetang/how 此处有获取方法
        self.night_sgin = '{"Reason":"","AttachmentFileName":"","LngLat":"118.365011,24.445686","Address":"福建省泉州市金门县电动车充电站(金湖镇公所)"}'



    def login(self):
        params = {
            "mobile": self.mobile,
            "password": encryptPassword(self.password),
            "ct": "2",
            "identify": "0",
        }

        # 登录接口
        response = self.request("https://mobile.yiban.cn/api/v4/passport/login", method="post", params=params, cookies=self.COOKIES)
        if response is not None and response["response"] == 100:
            self.access_token = response["data"]["access_token"]
            self.HEADERS["Authorization"] = "Bearer " + self.access_token
            self.COOKIES["loginToken"] = self.access_token  # 添加COOKIES字段
            return response
        else:
            return response
    # 重定向认证    
    def auth(self) -> json:
        act = self.session.get("http://f.yiban.cn/iapp/index?act=iapp7463", allow_redirects=False, 
                                cookies=self.COOKIES).headers["Location"] # Response [302] 重定向
        verifyRequest = re.findall(r"verify_request=(.*?)&", act)[0]
        self.HEADERS.update({
            'origin': 'https://app.uyiban.com',
            'referer': 'https://app.uyiban.com/',
            'Host': 'api.uyiban.com',
            'user-agent': 'YiBan/5.0.1'
        })
        response = self.request(
            "https://api.uyiban.com/base/c/auth/yiban?verifyRequest=" + verifyRequest + "&CSRF=" + self.CSRF,
            cookies=self.COOKIES)
        return response
        
    def request(self, url, method="get", params=None, cookies=None):
        if method == "get":
            response = self.session.get(url=url, timeout=10, headers=self.HEADERS, params=params, cookies=cookies)
        elif method == "post":
            response = self.session.post(url=url, timeout=10, headers=self.HEADERS, data=params, cookies=cookies)

        return response.json()


    def sginPostion(self):
        return self.request(url="https://api.uyiban.com/nightAttendance/student/index/signPosition?CSRF=" + self.CSRF,
                            cookies=self.COOKIES)
    
    def nightAttendance(self, info) -> json:
        params = {
            "Code": "",
            "PhoneModel": "",
            "SignInfo": info,
            "OutState": "1"
        }
        response = self.request("https://api.uyiban.com/nightAttendance/student/index/signIn?CSRF=" + self.CSRF,
                                method="post", params=params, cookies=self.COOKIES)
        return response
        
    def setall(self):
        self.login()
        self.auth()
        time.sleep(3)
        self.sginPostion()
        time.sleep(2)
        status = self.nightAttendance(self.night_sgin)
        sendEmail()
        return status

def main():
    # 修改下方的手机号和 密码
    a = yiban("手机号", "密码")
    status = a.setall()
    print(status)
    time.sleep(1)
    
if __name__ == '__main__':
    main()
    
