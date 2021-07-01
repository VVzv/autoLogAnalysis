# !/usr/bin/python
# -*- coding:utf-8 -*-
# __Author__: VVzv

import os
import re
import sys
import time
import json
import random
import requests
import warnings
warnings.filterwarnings('ignore')

import jieba
import geoip2.database
from pyecharts.charts import *
from pyecharts import options as opts
from pyecharts.commons.utils import JsCode

from urllib import parse
from bs4 import BeautifulSoup

from colorama import init
if sys.platform.lower() == "win32":
    init(autoreset=True)


now_date = time.strftime("%Y_%m_%d", time.localtime())
# 保存文件名称
rel_path = now_date + "_access_log_analysis_result.html"

start_time = time.time()
# 将log中英文日期转换为数字，方便后面转时间戳
month_dict = {"Jan": "01", "Feb": "02", "Mar": "03", "Apr": "04", "May": "05", "Jun": "06", "Jul": "07", "Aug": "08", "Sept": "09", "Oct": "10", "Nov": "11", "Dec": "12"}
# 漏洞规则保存位置（暂时遗弃）
yara_path  = "./yara/vulnYara.json"
# geoip2数据路径
geoip_database_path = "./MapDB/GeoLite2-City.mmdb"

ua_list = [
    "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_5_4; en-gb) AppleWebKit/528.4+ (KHTML, like Gecko) Version/4.0dp1 Safari/526.11.2",
    "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_5_4; en-us) AppleWebKit/528.4+ (KHTML, like Gecko) Version/4.0dp1 Safari/526.11.2",
    "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_5_6; en-US) AppleWebKit/530.5 (KHTML, like Gecko) Chrome/ Safari/530.5",
    "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_5_6; en-US) AppleWebKit/530.6 (KHTML, like Gecko) Chrome/ Safari/530.6",
    "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_5_6; en-US) AppleWebKit/530.9 (KHTML, like Gecko) Chrome/ Safari/530.9",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/21.0.1180.71 Safari/537.1 LBBROWSER",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.84 Safari/535.11 LBBROWSER",
]

# 需要匹配200、302、304状态码(暂时遗弃)
# status_code_match    = re.compile("200|302|304")
# 特殊符号
special_symbols      = ["\n", "\t", "\f", "\r"]
# 需要过滤的URI后缀，搜索时忽略大小写
uri_suffix_filter    = re.compile("\.js|\.png|\.jpg|\.gif|\.ttf|\.svg|\.css|\.map|\.mp3|\.pdf|\.swf|captcha|\.ico|\.txt|\.woff|ajax\?|css", re.IGNORECASE)
# 漏洞关键词
vuln_key_word_filter = ['注入', '代码执行', '命令执行', 'XSS', 'SSRF', '反序列化', '文件包含', '漏洞利用']
# 文件后缀和关键词
uri_suffix_file_dict = {
    # "数据库文件扫描": ['.sql', '.mdb', '.pgsql', 'database.'],
    # "备份文件扫描": ['.zip', '.tar', '.gz', '.rar', '.tar', '.7z'],
    # "PHP路径扫描": ['.php', '.ph'],
    # "JSP路径扫描": ['.jsp', '.jspx'],
    # "ASP路径扫描": ['.asp', '.aspx', '.ashx'],
    # "CGI文件扫描": ['.cgi'],
    # "HTML路径扫描": ['.html', '.htm', '.shtml']
    "敏感文件/路径扫描": ['.sql', '.mdb', '.pgsql', 'database', '.zip', '.tar', '.gz', '.rar', '.tar', '.7z', '.php', '.ph', '.jsp', '.jspx', '.asp', '.aspx', '.ashx', '.html', '.htm', '.shtml', '.cgi', '/cgi', 'config', '.log', 'console', '.cfm', 'jhtml', '.htw', '.bak', '.xml', '.swf', 'jboss', 'Servlet', '.action', '.svn', '.git', '.htaccess', '.ini', '.cnf', '.conf', 'phpmyadmin', '.myd', '/pmd/']
}
# 漏洞关键词字典
vuln_key_word_dict = {
    "Webshell上传": ["<\?php .*?>", "<%.*?VBScript.*?>.*?", '<%.*?%>'],
    "SQL注入攻击": ['select ', 'union ', 'if\(', 'from', 'sleep\(', 'information_', 'waitfor delay', ' or ', ' and ', 'substr\(', 'ascii\(', 'substring\(', 'XOR\(', '\(select '],
    "命令/代码执行": ['nslookup', 'wget', 'curl', 'whoami', '\w+\=id', '\Wecho[\W]', ';print\(\"', 'system\(\"', 'call_\w', 'echo.*?base64', 'phpinfo', 'exec\([\w|\W]'],
    "反序列化漏洞": ["[\w|\W]\{.*?:.*?:.*?\}", '[\w|\W]\{.*?java.*?\}'],
    "模版注入": ['[\w|\W]\{.*?\..*?\..*?\}'],
    "文件包含漏洞": ['php://input', 'php://filter/\w+', 'data://.*?base64[\w|\W]', '\=phar://\w+', '=zip://\w+'],
    "路径穿越": ["\.\./(.*?)\w$", "\.\.\(_\)(.*?)\w$", "\./(.*?)\w$", "file:///", "/etc/passwd", "windows/win.ini", "\.\./\.\./\w+"],
    "跨站脚本攻击(XSS)": ['( on\=.*?)', '"><[\w|\W]', '<\w+.*?on.*?=', '"on\w+\=', '\'><[\w|\W]', '[\w|\W]alert[\w|\W]', '<.*?src=', 'javascript[\w|\W]', '[\w|\W]<!--', '[\w|\W]prompt[\w|\W]', '<script>.*?</script>', 'document\.'],
    "服务器请求伪造攻击(SSRF)": ['\=http://\d+\.', '\=https://\d+\.', "\=file:///", '\=dict://\d+\.', '\=gopher://', "\=phar://", "\=ftp://\d+\.", "\=jar://"],
    "目录探测": ['/(.*?)/$', "^\.(.*?)/$"],
}

# 漏洞风险等级（为了便于输入颜色的修改）
vuln_grade_high   = re.compile("执行|注入|Webshell|反序列|存储|SSRF|包含|XXE|未授权")
vuln_grade_middle = re.compile("穿越|探测|目录|XSS|CSRF|扫描")

# 进行高分析分析的关键词（暂时遗弃）
# second_analyze_keyword = ["Webshell", "命令/代码执行"]
# 进行百度搜索匹配漏洞名称关键词
search_vuln_name_keyword = ["=call_\w", "=file_\w"]
# 扫描器指纹信息
scan_device_fingerprint = {
    "AWVS": ['acunetix', 'http://testasp.vulnweb.com'],
    "Nessus": ['nessus'],
}
# 资产名称（后续在添加）
# assets_name_dict = {"phpmyadmin路径扫描": ['phpmyadmin', 'pma'], "WordPress路径扫描": ['wp']}

# 添加日志中白名单关键词，在做分析前请人工简单过下日志，添加状态码为200的白名单，除去过滤后缀的
# 或者先用脚本进行分析，然后正在添加，多次分析，输出最终分析结果(暂时弃用)
# white_key_list  = ['']
# 单秒请求次数阀值(暂时弃用)
# second_threshold = 7
# 全局有效uri列表（暂时弃用）
# global_runtime_eff_uri_list = []


class ColorPrint:
    def redPrint(self, info):
        print("\033[31m{}\033[0m".format(info))

    def cyanPrint(self, info):
        print("\033[36m{}\033[0m".format(info))

    def yellowPrint(self, info):
        print("\033[33m{}\033[0m".format(info))

    def greenPrint(self, info):
        print("\033[32m{}\033[0m".format(info))

    def magentaPrint(self, info):
        print("\033[35m{}\033[0m".format(info))

    def bluePrint(self, info):
        print("\033[34m{}\033[0m".format(info))


class NginxAccessLogAnalyze(ColorPrint):

    def __init__(self, log_path):
        self.log_path                = log_path
        self.vuln_yara               = json.loads(open(yara_path, 'r').read())
        self.vuln_ip_addr            = {}
        self.vuln_count_dict         = {}
        self.attack_vuln_dis         = {}
        self.webshell_act_dict       = {}
        self._webshell_trace         = {}
        self.webshell_req_dict       = {}
        self.draw_webshell_trace_map = False

    # 将log日志中的时间转换为时间戳
    def time2stamp(self, format_time):
        time_array = time.strptime(format_time, "%d/%m/%Y:%H:%M:%S")
        time_stamp = int(time.mktime(time_array))
        return time_stamp

    def getLogTimeStamp(self, log_info):
        '''
        :param log_info: 单条日志内容
        :return: 2021-01-01 11:11:11 这种时间格式
        '''
        time_format = re.findall("\[(\w+/\w+/\w+:\w+:\w+:\w+) \+\d+\]", log_info)
        get_month_in_time = time_format[0].split("/")[1]
        log_time = time_format[0].replace(get_month_in_time, month_dict[get_month_in_time])
        time_array = time.strptime(log_time, "%d/%m/%Y:%H:%M:%S")
        time_stamp = int(time.mktime(time_array))
        _date = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time_stamp))
        return _date

    # 将log日志但行内容转换为列表类型
    def logFilter(self, log_text):
        '''
        :param log_text: 单条日志内容
        :return: [IP地址, 时间, 请求方式, URL, 状态码, 响应长度]， 如果没有匹配到规则，则返回None
        '''
        log_text = log_text.strip()
        for ss in special_symbols:
            if ss in log_text:
                log_text = log_text.replace(ss, "")
        log_filter = []
        # 过滤规则
        ip_filter = re.compile("([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}) - -")
        time_filter = re.compile("\[(\w+/\w+/\w+:\w+:\w+:\w+) \+\d+\]")
        method_filter = re.compile("\"([A-Za-z]{3,7}) ")  # {3,4}代表只匹配GET/POST/MOVE/PUT/HEAD，如要匹配OPTION修改为{3,7}
        uri_filter = re.compile("\"[A-Za-z]{3,7} ([/|\W].*?) HTTP/[\d]\.[\d]")
        status_code_filter = re.compile("\" ([\d]{3}) ")

        ip_address_get = re.findall(ip_filter, log_text)
        if len(ip_address_get) != 0:
            log_filter.append(ip_address_get[0])
        else:
            log_filter.append("Not find")

        log_time_get = re.findall(time_filter, log_text)
        if len(log_time_get) != 0:
            get_month_in_time = log_time_get[0].split("/")[1]
            log_time = log_time_get[0].replace(get_month_in_time, month_dict[get_month_in_time])
            time_array = time.strptime(log_time, "%d/%m/%Y:%H:%M:%S")
            time_stamp = int(time.mktime(time_array))  # 将输出的时间转换为时间戳，以便于计算
            log_filter.append(time_stamp)
        else:
            log_filter.append("Not find")

        req_method_get = re.findall(method_filter, log_text)
        if len(req_method_get) != 0:
            log_filter.append(req_method_get[0])
        else:
            log_filter.append("Not find")

        req_uri_get = re.findall(uri_filter, log_text)
        if len(req_uri_get) != 0:
            log_filter.append(parse.unquote(req_uri_get[0]))
        else:
            log_filter.append("Not find")

        res_status_code_get = re.findall(status_code_filter, log_text)
        if len(res_status_code_get) != 0:
            log_filter.append(res_status_code_get[0])
        else:
            log_filter.append("Not find")

        # 获取响应数据大小，以便于后面判断响应是否有效
        log_filter.append(log_text.split(" ")[-1])
        # print(log_filter)
        if "Not find" not in log_filter:
            return log_filter
        else:
            return None

    # URI匹配本地规则
    def yaraVuln(self, log_uri):
        try:
            return self.vuln_yara[log_uri]
        except:
            return None

    def writeYara(self, uri_info, vuln_name):
        self.vuln_yara.update({uri_info: vuln_name})
        with open(yara_path, 'w') as f:
            json.dump(self.vuln_yara, f)

    # 二次全攻击类型判断
    def guessVuln(self, log_info):
        rex_uri = re.findall("\"[A-Za-z]{3,7} (/.*?) HTTP/[\d]\.[\d]", log_info)
        if len(rex_uri) == 0:
            return None
        else:
            uri_info = rex_uri[0]
            # print(uri_info)
            # 漏洞类型关键词判断
            for vkwd in vuln_key_word_dict.items():
                for k in vkwd[1]:
                    if re.search(k, uri_info, re.IGNORECASE):
                        # print(u"\033[36m[*][{}]\033[0m\033[1;31m[{}]\033[0m\033[35m {}\033[0m".format(
                        #     time.strftime("%H:%M:%S", time.localtime()), vkwd[0], parse.unquote(uri_info)
                        # ))
                        return [vkwd[0], uri_info]
            # 后缀判断
            for fd in uri_suffix_file_dict.items():
                for suffix in fd[1]:
                    if suffix in uri_info.lower(): #and "=" not in uri_info:
                        # print(u"\033[36m[*][{}]\033[0m\033[1;31m[{}]\033[0m\033[35m {}\033[0m".format(
                        #     time.strftime("%H:%M:%S", time.localtime()), fd[0], parse.unquote(uri_info)
                        # ))
                        return [fd[0], uri_info]

    # 暂时先取消，这个可以用于以后多日志获取yara规则来进行
    # 根据uri内容判断其漏洞名称
    # 通过百度搜索，然后在使用jieba分词进行判定
    # 为了减少百度搜索时间，将匹配到的规则保存到本地json中，如果下次匹配出来就不用在进行百度搜索，如果没匹配出来在进行百度搜索然后添加新规则
    def  searchVulnName(self, uri_info):
        vuln_name = self.yaraVuln(uri_info)
        if vuln_name:
            # print("\033[36m[*][{}]\033[0m\033[1;31m[{}]\033[0m\033[35m {}\033[0m".format(
            #     time.strftime("%H:%M:%S", time.localtime()), vuln_name, parse.unquote(uri_info)
            # ))
            return vuln_name
        else:
            # 排除URL中是index.xxx开始并结束的
            if re.search("^/index\.[a-zA-Z]+$", uri_info):
                return None
            # 排除URL中存在中文的
            if re.findall("=([\u4e00-\u9fff]+)", uri_info):
                return None
            # 下面是采用百度搜索匹配关键词判断漏洞的
            # time.sleep(random.uniform(0.1, 0.5))  # 加点延时，防止百度反爬
            headers = {
                "Host": "www.baidu.com",
                "User-Agent": random.choices(ua_list)[0],
                "Cookie": "BAIDUID=39B9CF98EE252213FE5549E5A950F198:FG=1; BIDUPSID=39B9CF98EE252213AD876D836CE567D2; PSTM=1606046190; COOKIE_SESSION=67_0_2_2_0_1_1_0_2_1_1_0_0_0_0_0_0_0_1617791571%7C2%230_0_1617791571%7C1; BAIDUID_BFESS=39B9CF98EE252213FE5549E5A950F198:FG=1; __yjs_duid=1_7796310f78e76819111f5df3ab5b86e01617791574519; BD_HOME=1; H_PS_PSSID=33986_33820_33848_33756_33607_33996; BD_UPN=123253; BA_HECTOR=84018g0125bl8080vv1g96ul00r; WWW_ST={}".format(int(time.time())),
            }
            vuln_search_str = ""
            # 百度搜索
            url = "https://www.baidu.com/s?ie=utf-8&mod=1&isbd=1&isid=df17aee20026f28d&ie=utf-8&f=8&rsv_bp=1&tn=baidu&wd="
            req = requests.get(url + uri_info, headers=headers)
            if req.status_code == 200 and "漏洞" in  req.text:
                soup = BeautifulSoup(req.text, "lxml")
                search_list = soup.find_all("div", class_="result c-container new-pmd")
                for s in search_list:
                    try:
                        title = s.find("h3").text
                        content = s.find("div", class_="c-abstract").text
                        if ")" in title:
                            title = title.split(")")[-1]
                        if "+" in title:
                            title = title.split("+")[0]
                        if "]" in title:
                            title = title.split("]")[-1]
                        if "---" in title:
                            title = title.split("-")[-1]
                        if "-" in title:
                            title = title.split("-")[0]
                        if "_" in title:
                            title = title.split("_")[0]
                        title = title.strip()
                        uri_key = uri_info.split("/")
                        c = 0
                        vc = 0
                        for k in uri_key:
                            for vk in vuln_key_word_filter:
                                if vk in title:
                                    vc = 1
                                    break
                            if c >= 1:
                                vuln_search_str += title + "\n"
                                break
                            elif vc:
                                if "login" != k.lower() and "index" != k.lower() and (k in title or k in content):
                                    c += 1
                    except:
                        pass
            else:
                return None
            # 进行百度搜索单页分词判断，根据筛选的词评率组合进行漏洞判断
            words_list = jieba.lcut(vuln_search_str)
            words_counts_dict = {}
            for w in words_list:
                if len(w) == 1:
                    continue
                else:
                    words_counts_dict[w] = words_counts_dict.get(w, 0) + 1
            words_items = list(words_counts_dict.items())
            words_items.sort(key=lambda x: x[1], reverse=True)
            # print(words_items)
            search_title_content = vuln_search_str.split("\n")
            vuln_name = ""
            for t in search_title_content:
                # 判断单页搜索内容中前两个词均存在的title即为漏洞名称
                if len(words_list) > 1:
                    if words_list[0] in t and words_items[1][0] in t:
                        vuln_name = t
                        break

            if '】' in vuln_name:
                vuln_name = vuln_name.split("】")[-1]
            for suffix_vu in vuln_key_word_filter:
                if suffix_vu in vuln_name:
                    vuln_name = vuln_name.split(suffix_vu)[0]
                    if len(vuln_name) > 3:
                        vuln_name += suffix_vu
                        # print("\033[36m[*][{}]\033[0m\033[1;31m[{}]\033[0m\033[35m {}\033[0m".format(
                        #         time.strftime("%H:%M:%S", time.localtime()), vuln_name, parse.unquote(uri_info)
                        #     ))
                        self.writeYara(uri_info, vuln_name)
                        return vuln_name

    # 漏洞规则排查每条日志
    def ruleRegx(self, lg):
        lg = parse.unquote(lg)
        for k, v in vuln_key_word_dict.items():
            for v_ru in v:
                if (re.findall(v_ru, lg, re.IGNORECASE)) and not re.findall(uri_suffix_filter, lg):
                    return [k, v_ru, lg]

    # 记录每个匹配规则IP地址的次数
    def vulnIpAddr(self, ip_addr):
        try:
            self.vuln_ip_addr[ip_addr] += 1
        except:
            self.vuln_ip_addr.update({ip_addr: 1})

    def vulnCount(self, vuln_name):
        try:
            self.vuln_count_dict[vuln_name] += 1
        except:
            self.vuln_count_dict.update({vuln_name: 1})

    # 攻击者信息记录
    def attackDict(self, ck_list):
        try:
            try:
                self.attack_vuln_dis[ck_list[0]][ck_list[-1]] += 1
            except:
                self.attack_vuln_dis[ck_list[0]].update({ck_list[-1]: 1})
        except:
            self.attack_vuln_dis.update({ck_list[0]: {ck_list[-1]: 1}})

    # 开始分析并转换为固定格式
    def autoAny(self, one_log):
        # vuln_regx_log = [漏洞规则名称, 匹配的规则, 日志]
        vuln_regx_log = self.ruleRegx(one_log)
        # 判断非None和状态码200的特征
        if vuln_regx_log != None and "\" 200 " in vuln_regx_log[-1]:
            #log_list = [ip, 时间戳, 请求方式, uri, 状态码, 响应大小, 漏洞名称]
            log_list = self.logFilter(vuln_regx_log[-1])
            vuln_name = vuln_regx_log[0] #self.guessVuln(log_list[3])
            if vuln_name:
                if vuln_name == "Webshell上传":
                    try:
                        self.webshell_act_dict[log_list[0]].append(log_list)
                    except:
                        self.webshell_act_dict.update({log_list[0]: [log_list]})
                log_list.append(vuln_name)
                self.vulnIpAddr(log_list[0])
                self.vulnCount(vuln_name)
                self.attackDict(log_list)
            # print(self.vuln_ip_addr)
            # print(self.vuln_count_dict)

    # TOP10排序
    def top10Sort(self, info_dict):
        # 对IP字典根据其values值进行排序（从大到小）
        count_sorted_list = sorted(info_dict.items(), key=lambda x: (x[1], x[0]), reverse=True)
        if len(count_sorted_list) <= 10:
            ip_top_10 = count_sorted_list[::-1]
        else:
            ip_top_10 = count_sorted_list[:10][::-1]
        return ip_top_10

    def topOneAny(self):
        '''
        :return: [IP地址, 总攻击次数, 攻击有效次数(返回状态码200), 攻击起始时间, 攻击结束时间, {攻击类型统计}]
        '''
        self.cyanPrint("[*][{}] 正在分析攻击TOP1地址信息...".format(time.strftime("%H:%M:%S", time.localtime())))
        top_10_list = self.top10Sort(self.vuln_ip_addr)[::-1]
        # top_10_list = [('8.131.102.198', 1), ('8.133.170.246', 1), ('8.133.171.26', 1), ('39.106.91.233', 2), ('111.221.46.15', 4), ('47.110.180.33', 4), ('47.110.180.46', 4), ('107.161.50.66', 5), ('117.50.18.16', 153), ('183.136.190.62', 3267)][::-1]
        top_one_ip = top_10_list[0]
        ip_all_attack = 0
        attack_effective = 0
        attack_start_time = 0
        start_count = True
        attack_end_time = 0
        attack_info = {}
        count = 0
        now_time = time.strftime("%H:%M:%S", time.localtime())
        with open(self.log_path) as f:
            for l in f:
                if top_one_ip[0] in l and start_count == True:
                    attack_start_time = self.getLogTimeStamp(l)
                    start_count = False
                if top_one_ip[0] in l:
                    ip_all_attack += 1
                    attack_end_time = self.getLogTimeStamp(l)
                    guess_name = self.guessVuln(l)
                    if guess_name:
                        if count == 0:
                            sys.stdout.write('\r\033[36m[{1}][{0}]\033[0m\033[1;31m[{2}]\033[0m \033[1;35m{3}\033[0m'.format(now_time, '\\', guess_name[0], guess_name[1]))
                            count = 1
                        elif count == 1:
                            sys.stdout.write('\r\033[36m[{1}][{0}]\033[0m\033[1;31m[{2}]\033[0m \033[1;35m{3}\033[0m'.format(now_time, '-', guess_name[0], guess_name[1]))
                            count = 2
                        else:
                            sys.stdout.write('\r\033[36m[{1}][{0}]\033[0m\033[1;31m[{2}]\033[0m \033[1;35m{3}\033[0m'.format(now_time, '/', guess_name[0], guess_name[1]))
                            count = 0
                        sys.stdout.flush()
                        try:
                            attack_info[guess_name[0]] += 1
                        except:
                            attack_info.update({guess_name[0]: 1})
                    if '" 200 ' in l and guess_name:
                        attack_effective += 1
        self.cyanPrint("\r[*][{}] 攻击TOP1分析完成...".format(time.strftime("%H:%M:%S", time.localtime())))
        return [top_one_ip[0], ip_all_attack, attack_effective, attack_start_time, attack_end_time, attack_info]

    # webshell文件上传追踪，目前只能追踪GET请求发起的
    def webShellAny(self):
        '''
        :return: {IP地址: [[时间, 请求方式, 上传路径, 文件内容, 状态码, 响应大小, 漏洞名称]]}
        :retirn -> self._webshell_trace
        '''
        self.redPrint("[+][{}] 发现Webshell上传日志，正在进行追踪分析...".format(time.strftime("%H:%M:%S", time.localtime())))
        up_shell_re_list = ["[&|?]\w+\=(.*?\.ph\w+)[|&]" ,"[&|?]\w+\=(.*?\.js[p-x]{1,2})[|&]", "[&|?]\w+\=(.*?\.as[p-x]{1,2})[|&]", "[&|?]\w+\=(.*?\.ashx)[|&]"]
        # 调试值
        # self.webshell_act_dict = {'111.221.46.15': [['111.221.46.15', 1618075124, 'GET', '/index.php?s=index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=file_put_contents&vars[1][]=d.php&vars[1][]=<?php @eval($_POST[spread]);?>', '200', '6163', 'Webshell上传'], ['111.221.46.15', 1618075126, 'GET', '/index.php?s=index/\\think\\Container/invokefunction&function=call_user_func_array&vars[0]=file_put_contents&vars[1][]=d.php&vars[1][]=<?php @eval($_POST[spread]);?>', '200', '6163', 'Webshell上传'], ['111.221.46.15', 1618075131, 'GET', '/index.php?s=index/\\think\\Request/input&cacheFile=d.php&content=<?php @eval($_POST[spread]);?>', '200', '6163', 'Webshell上传'], ['111.221.46.15', 1618075133, 'GET', '/index.php?s=index/\\think\\view\\driver\\Php/display&cacheFile=d.php&content=<?php @eval($_POST[spread]);?>', '200', '6163', 'Webshell上传']]}
        for k, v in self.webshell_act_dict.items():
            for value in v:
                up_file_path = ''
                shell_content = ''
                vuln_name = self.searchVulnName(value[3])
                if not vuln_name:
                    vuln_name = "无"
                for rex in vuln_key_word_dict["Webshell上传"]:
                    webshell_content = re.findall(rex, value[3])
                    if webshell_content:
                       shell_content = webshell_content[0]
                for up_rex in up_shell_re_list:
                    up_file_name = re.findall(up_rex, value[3], re.IGNORECASE)
                    if up_file_name:
                        if "&" in up_file_name[0]:
                            # print(up_file_name)
                            file_split_1 = up_file_name[0].split("&")[0]
                            file_split_2 = up_file_name[0].split("&")[-1]
                            if "\\" in file_split_1 or "/" in file_split_1:
                                file_path = file_split_1 + '/'
                            if "=" in file_split_2:
                                file_name = file_split_2.split("=")[-1]
                            up_file_path = file_path + file_name
                        elif "=" in up_file_name[0]:
                            up_file_path = up_file_name[0].split("=")[-1]
                        else:
                            up_file_path = up_file_name[0]
                        # print(up_file_path)
                try:
                    self._webshell_trace[k].append([time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(value[1])), value[2], up_file_path, shell_content, value[4], value[5], vuln_name])
                except:
                    self._webshell_trace.update({k: [[time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(value[1])), value[2], up_file_path, shell_content, value[4], value[5], vuln_name]]})

    # webshell连接日志分析，输出树状图json格式
    def webShellTrace(self):
        # 调试值
        # self._webshell_trace = {'111.221.46.15': [['2021-04-11 01:18:44', 'GET', 'index/\\think\\app/invokefunction/d.php', '<?php @eval($_POST[spread]);?>', '200', '6163', 'thinkphp5.x远程代码执行漏洞'], ['2021-04-11 01:18:46', 'GET', 'index/\\think\\Container/invokefunction/d.php', '<?php @eval($_POST[spread]);?>', '200', '6163', 'thinkphp5.x远程代码执行漏洞'], ['2021-04-11 01:18:51', 'GET', 'index/\\think\\Request/input/zeyan-53132678.jsp', '<?php @eval($_POST[spread]);?>', '200', '6163', 'thinkphp5.x远程代码执行漏洞'], ['2021-04-11 01:18:53', 'GET', 'index/\\think\\view\\driver\\Php/display/d.php', '<?php @eval($_POST[spread]);?>', '200', '6163', 'thinkphp5.x远程代码执行漏洞']], "183.136.190.62": [['2021-04-11 01:18:53', 'GET', 'index/\\think\\view\\driver\\Php/display/zeyan-53132678.jsp', '<?php @eval($_POST[spread]);?>', '200', '6163', 'thinkphp5.x远程代码执行漏洞']]}
        self.webshell_req_dict = {"name": "WebShell分析树", "children": []}
        webshell_file_name = {}
        count = 0
        if self._webshell_trace:
            for k,v in self._webshell_trace.items():
                self.webshell_req_dict["children"].append({"name": k})
                self.webshell_req_dict["children"][count].update({"children": []})
                runtime_name = []
                for value in v:
                    if str(type(value)) == "<class 'list'>":
                        file_name = "/" + value[2].split("/")[-1]
                        if file_name not in runtime_name:
                            runtime_name.append(file_name)
                            try:
                                webshell_file_name[k].append(file_name)
                            except:
                                webshell_file_name.update({k: [file_name]})
                            self.webshell_req_dict["children"][count]["children"].append({"name": file_name, "children": []})
                count += 1
        count_k = 0
        # print(self.webshell_req_dict)
        for k, v in webshell_file_name.items():
            _runtime = {}
            for value in v:
                _runtime.update({value: []})
            # _run_list = []
            with open(self.log_path, "r") as f:
                for s in f:
                    for fn in v:
                        if fn in s:
                            log_format = self.logFilter(s)
                            if log_format:
                                log_format[1] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(log_format[1]))
                                if log_format[0] not in _runtime[fn]:
                                    _runtime[fn].append(log_format[0])
                                    self.webshell_req_dict["children"][count_k]["children"][v.index(fn)]["children"].append({"name": log_format[0], "children": [{"name": log_format[-3], "children": [{"name": log_format[-2]}]}]})
                                else:
                                    self.webshell_req_dict["children"][count_k]["children"][v.index(fn)]["children"][_runtime[fn].index(log_format[0])]["children"].append({"name": log_format[-3], "children": [{"name": log_format[-2]}]})
            count_k += 1


# 绘制图表
class DrawAny(NginxAccessLogAnalyze):

    # 获取IP地址归属国家，绘制世界地图
    def getLocaltion(self):
        g = geoip2.database.Reader(geoip_database_path)
        # print(self.vuln_ip_addr)
        ip_location_dict = {}
        for k, v in self.vuln_ip_addr.items():
            rec = g.city(k)
            ip_country = rec.country.name #names['zh-CN'] 目前发现如果是中文的，地图上不会显示信息，后续在研究
            try:
                ip_location_dict[ip_country] += v
            except:
                ip_location_dict.update({ip_country: v})
        return ip_location_dict

    # 攻击类型统计
    def drawVulnType(self):
        grid = Grid(init_opts=opts.InitOpts(width="1400px", height="800px"))
        vuln_count_dict = self.top10Sort(self.vuln_count_dict)
        data_list = [[1, vv, kk] for kk, vv in vuln_count_dict]
        for d in data_list:
            if re.search(vuln_grade_high, d[-1]):
                d[0] = 3
            elif re.search(vuln_grade_middle, d[-1]):
                d[0] = 2
        data_list.insert(0, ["风险等级", "漏洞类型个数", "漏洞类型"])
        bar = Bar()
        bar.add_dataset(
            source=data_list
        )
        bar.set_global_opts(
            title_opts=opts.TitleOpts(title="日志攻击漏洞分析\n", pos_left="center"),
            xaxis_opts=opts.AxisOpts(name="漏洞类型个数"),
            yaxis_opts=opts.AxisOpts(type_="category"),
            visualmap_opts=opts.VisualMapOpts(
                orient="horizontal",
                pos_left="center",
                min_=1,
                max_=3,
                range_text=["高风险", "低风险"],
                dimension=0,
                range_color=["#00FF00", "yellow", "#FF0000"],
            ),
        )
        bar.add_yaxis(
            series_name="",
            y_axis=[],
            encode={"x": "漏洞类型个数", "y": "漏洞类型"},
            label_opts=opts.LabelOpts(is_show=True, position="right", color="black"),  # y轴数据标签值
        )
        grid.add(bar, grid_opts=opts.GridOpts(is_contain_label=True))
        grid.render("draw_bar1.html")

    # 攻击地址统计
    def drawIpTop10(self):
        grid = Grid(init_opts=opts.InitOpts(width="1400px", height="800px"))
        top10_ip_addr = self.top10Sort(self.vuln_ip_addr)
        data_list = [[i, top10_ip_addr[i][-1], top10_ip_addr[i][0]] for i in range(len(top10_ip_addr))]
        for d in data_list:
            if re.search(vuln_grade_high, d[-1]):
                d[0] = 3
            elif re.search(vuln_grade_middle, d[-1]):
                d[0] = 2
        data_list.insert(0, ["TOP等级", "IP攻击次数", "IP地址"])
        bar = Bar(init_opts=opts.InitOpts(width="1400px", height="800px"))
        bar.add_dataset(
            source=data_list
        )
        bar.set_global_opts(
            title_opts=opts.TitleOpts(title="TOP10 IP攻击地址统计\n", pos_left="center"),
            xaxis_opts=opts.AxisOpts(name="IP攻击次数"),
            yaxis_opts=opts.AxisOpts(type_="category"),
            visualmap_opts=opts.VisualMapOpts(
                orient="horizontal",
                pos_left="center",
                min_=1,
                max_=10,
                range_text=["高", "低"],
                dimension=0,
                range_color=["#00FF00", "yellow", "#FF0000"],
            ),
        )
        bar.add_yaxis(
            series_name="",
            y_axis=[],
            encode={"x": "IP攻击次数", "y": "IP地址"},
            label_opts=opts.LabelOpts(is_show=True, position="right", color="black"),  # y轴数据标签值
        )
        grid.add(bar, grid_opts=opts.GridOpts(is_contain_label=True))
        grid.render("draw_bar2.html")

    def drawWorldMap(self):
        country_dict = self.getLocaltion()
        country_list = []
        for k, v in country_dict.items():
            country_list.append((k, v))

        map = Map(init_opts=opts.InitOpts(width="1400px", height="800px"))
        map.add(series_name="", data_pair=country_list, maptype="world")
        map.set_series_opts(label_opts=opts.LabelOpts(
            is_show=True,
            # 判断国家是否存在值，显示不为空的国家标题
            formatter=JsCode('''
                function(params) {
                    if (params.value) {
                        return params.name + '(' + params.value + ')';
                    } else {
                        return '';
                    }
                }''')
            ),
        )
        map.set_global_opts(
            title_opts=opts.TitleOpts(title="攻击地址归属地分布\n", pos_left="center"),
            visualmap_opts=opts.VisualMapOpts(
                orient="horizontal",
                pos_left="center",
                # min_=1,
                max_=5000,
                range_text=["高", "低"],
                dimension=0,
                range_color=["#00FF00", "yellow", "#FF0000"],
            ),
        )
        map.render("draw_map.html")

    # 绘制攻击类型饼图
    def drawPie(self, info_dict, ip_addr):
        '''
        :param info_dict:
        :param ip_addr:
        :return:
        '''
        data_pair = [[k, v] for k, v in info_dict.items()]
        data_pair.sort(key=lambda x: x[1])
        color_list = ["green", "#006400", "#00BFFF", "#1E90FF", "#4169E1", "#8A2BE2", "#FFA500", "#FF8C00", "#FF00FF", "#FF7F50", "red"]
        print(color_list[:len(data_pair) - 1].append(color_list[-1]))
        draw_color = color_list[:len(data_pair) - 1]
        draw_color.append(color_list[-1])
        # init_opts=opts.InitOpts(width="1600px", height="800px")
        pie = Pie(init_opts=opts.InitOpts(width="1400px", height="800px"))
        pie.add(
                series_name="漏洞类型",
                data_pair=data_pair,
                rosetype="radius",
                radius="55%",
                center=["50%", "50%"],
                label_opts=opts.LabelOpts(is_show=False, position="center"),
            )

        pie.set_colors(draw_color)
        pie.set_global_opts(
                title_opts=opts.TitleOpts(
                    title=ip_addr + "攻击类型统计",
                    pos_left="center",
                    pos_top="20",
                    title_textstyle_opts=opts.TextStyleOpts(color="#000000"),
                ),
                legend_opts=opts.LegendOpts(is_show=False),
            )
        pie.set_series_opts(
                tooltip_opts=opts.TooltipOpts(
                    trigger="item", formatter="{a} <br/>{b}: {c} ({d}%)"
                ),
                label_opts=opts.LabelOpts(
                    is_show=True,
                    formatter="{b}: {c} ({d}%)",
                    font_size=13,
                ),
            )
        pie.render("draw_pie.html")

    # 绘制攻击状图分布图
    def drawStatisticsPie(self, all_num, eff_num, ip_addr):
        '''
        :param all_num: TOP1攻击所有攻击请求次数
        :param eff_num: TOP1攻击所有有效攻击请求次数（状态码200）
        :param ip_addr: TOP1攻击地址
        :return:
        '''
        un_eff_num = all_num - eff_num
        data_pair = [
            ["攻击成功次数(200状态码)", eff_num],
            ["攻击失败次数", un_eff_num]
        ]
        pie = Pie(init_opts=opts.InitOpts(width="1400px", height="800px"))
        pie.add(
            series_name="攻击次数",
            data_pair=data_pair,
            rosetype="radius",
            radius="55%",
            center=["50%", "50%"],
            label_opts=opts.LabelOpts(is_show=False, position="center"),
        )
        pie.set_colors(['red', 'green'])
        pie.set_global_opts(
            title_opts=opts.TitleOpts(
                title=ip_addr + "攻击次数统计",
                pos_left="center",
                pos_top="20",
                title_textstyle_opts=opts.TextStyleOpts(color="#000000"),
            ),
            legend_opts=opts.LegendOpts(is_show=False),
        )
        pie.set_series_opts(
            tooltip_opts=opts.TooltipOpts(
                trigger="item", formatter="{a} <br/>{b}: {c} ({d}%)"
            ),
            label_opts=opts.LabelOpts(
                is_show=True,
                formatter="{b}: {c} ({d}%)",
                font_size=13,
            ),
        )
        pie.render("draw_stc_pie.html")

    # 绘制Webshell追踪树状图
    def drawTree(self):
        data = [self.webshell_req_dict]
        # init_opts=opts.InitOpts(width="1600px", height="800px")
        tree = Tree(init_opts=opts.InitOpts(width="1400px", height="800px"))
        # is_expand_and_collapse控制树结构是扩展还是折叠，False为展开状态，True为折叠状态
        tree.add("", data, is_expand_and_collapse=False)
        tree.set_global_opts(title_opts=opts.TitleOpts(
            title="WebShell上传访问追踪",
            pos_left="center",
            pos_top="20",
            title_textstyle_opts=opts.TextStyleOpts(color="#000000"))
        )
        tree.render("draw_tree_ws.html")

    def resultHtml(self):
        html_head = ""

        t1 = open("draw_bar1.html", 'r').read()
        t2 = open("draw_bar2.html", 'r').read()
        t3 = open("draw_map.html", 'r').read()
        t4 = open("draw_pie.html", 'r').read()
        t5 = open("draw_stc_pie.html", 'r').read()
        t6 = open("draw_tree_ws.html", 'r').read()
        webshell_explain = '<h3 align="center">webshell分析树->上传者->上传文件名称->访问上传文件者->访问结果</h1>'
        t7 = t1 + "\n" + t2 + "\n" + t3 + "\n" + t4 + "\n" + t5 + "\n" + t6 + "\n" + webshell_explain
        os.system("rm draw_bar1.html")
        os.system("rm draw_bar2.html")
        os.system("rm draw_map.html")
        os.system("rm draw_pie.html")
        os.system("rm draw_stc_pie.html")
        os.system("rm draw_tree_ws.html")
        with open(rel_path, 'w') as f:
            f.write(t7)

    # 主运行函数
    def main(self):
        self.cyanPrint("[*][%s] 正在分析日志文件%s" %(time.strftime("%H:%M:%S", time.localtime()), self.log_path))
        count = 0
        with open(self.log_path, 'r') as logf:
            for one_log in logf:
                self.autoAny(one_log)
                now_time = time.strftime("%H:%M:%S", time.localtime())
                # 显示一行内容
                if count == 0:
                    sys.stdout.write('\r\033[36m[{1}][{0}] 正在进行分析，请耐心等待...\033[0m'.format(now_time, '\\'))
                    count = 1
                elif count == 1:
                    sys.stdout.write('\r\033[36m[{1}][{0}] 正在进行分析，请耐心等待...\033[0m'.format(now_time, '-'))
                    count = 2
                else:
                    sys.stdout.write('\r\033[36m[{1}][{0}] 正在进行分析，请耐心等待...\033[0m'.format(now_time, '/'))
                    count = 0
                sys.stdout.flush()
        self.cyanPrint("\r[*][{}] 日志分析完成.".format(now_time))
        self.drawVulnType()
        self.drawIpTop10()
        self.drawWorldMap()
        if self.webshell_act_dict:
            self.webShellAny()
            if self._webshell_trace:
                self.webShellTrace()
                if self.webshell_req_dict:
                    self.drawTree()
                    self.magentaPrint("[*][{}] 追踪链分析完成，具体看分析结果。".format(now_time))
            else:
                self.magentaPrint("[!][{}] 从日志中未发现WebShell上传文件的利用链!".format(now_time))
        top_info = self.topOneAny()
        self.drawPie(top_info[-1], top_info[0])
        self.drawStatisticsPie(top_info[1], top_info[2], top_info[0])
        self.resultHtml()


if __name__ == '__main__':
    # 需要分析的日志路径
    # log_path = "access.log"
    banner = '''
[]\\\\     []   -----     [*][*]   [{}] 
|| \\\\    ||    [*]    ||      ||  
||  \\\\   ||    [*]    ||      ||   /——\\/
||   \\\\  ||    [*]    /\\      /\\   \\——/\\
||    \\\\ ||    [*]       [][]     g   ||
[]     \\\\[]    [*][*][*][*]       ————[]'''.format("Author@VVzv")
    print("\033[32m{}\033[0m".format(banner.strip()))
    log_path = input("请输入需要分析的Nginx日志路径:").strip()
    s_time =  time.time()
    d = DrawAny(log_path)
    d.main()
    # d.webShellTrace()
    # print(d.webshell_req_dict)
    e_time = time.time()
    use_time = int(e_time - s_time)
    use_min_time = use_time // 60
    use_sec_time = "{:02}".format(use_time % 60)
    ck_rel_path = os.getcwd() + rel_path
    print("\r\033[32m[+] 分析完成，共用时{}分{}秒，结果已输出到\"{}\"".format(use_min_time, use_sec_time, ck_rel_path))

