# mitmproxy-hedgehogcat

用 mitmproxy 保存某小说应用的小说

## 用法

1. 配置好 mitmproxy 环境，使它能正确解密应用的 https api 请求
2. mitmproxy 加载这个插件 `mitmproxy -s hbooker_mitm.py`
3. 在应用的书架中选择下载书籍，等待下载完成
4. `python 本插件.py 书籍ID(1000xxxx) 保存TXT名称`

## 功能

1. 保存应用对书籍信息、目录、下载章节的请求；根据请求生成书籍TXT
2. MITM修改书架请求，将下架书籍改为完结，启用书架中的下载按钮