# -*- coding: utf-8 -*-
import requests
import json
import re
import random
import base64
import os
import sys
import time
from crypter import aes_encrypt

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

class temperature:
    CSRF = "38717fe231a62f75253f9529f9e778d5"
    COOKIES = {"csrf_token": CSRF}
    HEADERS = {"Origin": "'https://m.yiban.cn", 'AppVersion': '5.0.4', "User-Agent": "Mozilla/5.0 (Linux; Android 11; MEIZU 18 Build/RKQ1.210715.001; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/93.0.4577.82 Mobile Safari/537.36"}
    AES_KEY = '2knV5VGRTScU7pOq'
    AES_IV = 'UmNWaNtM0PUdtFCs'

    task_once = {
    "a1b7d2e31196f36a1c34c68debaa7bb0": str(round(random.uniform(36.1, 36.9), 1)),
    "f6d71bcd48b01e5abe43d95c7a1d7c8b": "否",
    }
    timePeriod =  [
        time.strftime("%Y-%m-%d 6:00:00", time.localtime(int(time.time()))),
        time.strftime("%Y-%m-%d 18:00:00", time.localtime(int(time.time())))
    ]

    
    def __init__(self, mobile, password):
        self.mobile = mobile
        self.password = password
        self.session = requests.session()

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
    
    def getUncompletedList(self) -> json:
        #获取未完成的表单
        response = self.request("https://api.uyiban.com/officeTask/client/index/uncompletedList?CSRF=" + self.CSRF,
                                cookies=self.COOKIES)
        print(response)
        return response

    def getUncompletedListTime(self, st, et) -> json:
        """
        获取特定时间未完成的表单
        :return:
        """
        response = self.request(
            "https://api.uyiban.com/officeTask/client/index/uncompletedList?StartTime=" + st + "&EndTime=" + et + "&CSRF=" + self.CSRF,
            cookies=self.COOKIES)
        return response

    def getCompletedList(self) -> json:
        """
        获取已经完成的表单
        :return:
        """
        return self.request("https://api.uyiban.com/officeTask/client/index/completedList?CSRF=" + self.CSRF,
                            cookies=self.COOKIES)

    def getDetail(self, taskId) -> json:
        """
        获取表单WFId
        获取发布人信息,后面提交表单时要用到
        :param taskId:
        :return:
        """
        response = self.request(
            "https://api.uyiban.com/officeTask/client/index/detail?TaskId=" + taskId + "&CSRF=" + self.CSRF,
            cookies=self.COOKIES)
        self.WFId = response['data']['WFId']
        self.Title = response['data']["Title"]
        self.PubOrgName = response["data"]["PubOrgName"]
        self.PubPersonName = response["data"]["PubPersonName"]
        return response

    def getFormapi(self) -> json:
        """
        首次使用,需要创建提交表单用的数据
        此方法是用来创建表单数据的
        :return:
        """
        response = self.request("https://api.uyiban.com/workFlow/c/my/form/%s?CSRF=%s" % (self.WFId, self.CSRF),
                                cookies=self.COOKIES)
        return response


    def submitApply(self, data, extend) -> json:
        """
        提交表单
        :param data: 提交表单的参数
        :param extend: 发布人信息
        :return: 表单url
        """
        params = {
            "Data": json.dumps(data, ensure_ascii=False),
            "Extend": json.dumps(extend, ensure_ascii=False),
            "WFId": self.WFId
        }
        params = json.dumps(params, ensure_ascii=False)
        return self.request(
            "https://api.uyiban.com/workFlow/c/my/apply/?CSRF=%s" % (self.CSRF), method="post",
            params={'Str': aes_encrypt(self.AES_KEY, self.AES_IV, params)},
            cookies=self.COOKIES)

    def getShareUrl(self, key) -> json:
        """
        待更新....
        Key是随机生成的
        """
        return self.request(
            "https://app.uyiban.com/workFlow/client/#/share?Key=%s" % key,
            cookies=self.COOKIES)

    def setall(self):
        login = self.login()
        if (login["response"]) != 100:
            print(login["message"])
        else:
            auth = self.auth()
            if auth["code"] == 0:
                now_task = self.getUncompletedListTime(self.timePeriod[0],self.timePeriod[1])
                if not len(now_task["data"]):
                    print("没有找到需要提交的表单")

                else:
                    now_task_id = now_task["data"][0]["TaskId"]
                    detail = self.getDetail(now_task_id)
                    extend = {
                        "TaskId": now_task_id,
                        "title": "任务信息",
                        "content": [
                            {"label": "任务名称", "value": detail["data"]["Title"]},
                            {"label": "发布机构", "value": detail["data"]["PubOrgName"]},
                            {"label": "发布人", "value": detail["data"]["PubPersonName"]}
                        ]
                    }
                    #首次运行需要使用此方法获取表单数据
                    #self.getFormapi()
                    # 获取数据后，将需要提交的数据填充到task_once构造填写数据
                    sbmit_result = self.submitApply(self.task_once,extend)
                    if sbmit_result["code"] == 0:
                        result = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(time.time()))) + " 表单提交成功\n"
                        print(result)
                    return sbmit_result


def main():
    # 修改下方的手机号和密码
    a = temperature("手机号", "密码")
    status = a.setall()
    print(status)
    
if __name__ == '__main__':
    main()