# 易班定时健康打卡和晚点签到

> ## 文件说明

```python
│  crypter.py       		#表单提交时加密工具
│  puchCard.py 				#体温健康打卡工具
│  README.md
│  requirements.txt
│  utils.py
│  yibanAutoSgin.py			#晚点签到工具（配合GitHub actions使用）
│
│  yibanAutoSginLocal.py    #其他方式
├─.github
│  └─workflows
│          main.yml          #GitHub Actions 配置文件
```



> ##  使用方式

下载文件后需要在 pushCard.py 和 yibanAutoSgin.py 中修改自己的手机号和密码。

pushCard.py 首次运行时需要先获取需要上传的表单信息，然后在task_once中构造需要提交的表单数据。

yibanAutoSgin.py 中需要填写定位信息。

```python
     https://lbs.amap.com/tools/picker #寻找宿舍经纬度
     https://apecodewx.gitee.io/sixuetang/how #此处有获取方法
```

然后分别运行两个工具。

> ## 部署方式（自动运行）

1. GitHub actions

```python
自行研究
```



2. Linux服务器，crontab工具

```python
例如：
下面这个命令表示在每天的8:30分会执行任务,并将执行结果保存到文件中
30 8 * * * /usr/bin/python3 文件路径/xxxxx.py >> /log/log.txt
```



3. windows 定时任务

```python
自行研究
```

