# !/usr/bin/python
# -*- coding:utf-8 -*-
# __Author__: VVzv

import re
import time
import random
import requests
import warnings
warnings.filterwarnings('ignore')

import jieba

from urllib import parse
from bs4 import BeautifulSoup

'''
由于脚本是一次性读取整个日志文件，并且在分析过程中会请求百度根据uri判断漏洞名称，所以等结果需要一定时间
'''
start_time = time.time()
# 将log中英文日期转换为数字，方便后面转时间戳
month_dict = {"Jan": "01", "Feb": "02", "Mar": "03", "Apr": "04", "May": "05", "Jun": "06", "Jul": "07", "Aug": "08", "Sept": "09", "Oct": "10", "Nov": "11", "Dec": "12"}


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
status_code_match = re.compile("200|302|304")
# 需要过滤的URI后缀，搜索时忽略大小写
uri_suffix_filter  = re.compile("\.js|\.png|\.jpg|\.gif|\.ttf|\.svg|\.css|\.map|\.mp3|\.pdf|\.swf|captcha|\.ico|\.txt|\.woff|ajax\?|css", re.IGNORECASE)
# 漏洞关键词
vuln_key_word_filter =['注入', '代码执行', '命令执行', 'XSS', 'CSRF', 'SSRF', '反序列', '后台', '包含']
# 文件字典
uri_suffix_file_dict = {"数据库文件扫描": ['.sql', '.mdb'], "备份文件扫描": ['.zip', '.tar', '.gz', '.rar', '.tar', '.7z'], "PHP路径扫描":['.php', '.ph'], "JSP路径扫描": ['.jsp', '.jspx'], "ASP路径扫描": ['.asp', '.aspx'], "HTML路径扫描": ['.html', '.htm', '.shtml']}
# 漏洞关键词字典
vuln_key_word_dict = {"SQL注入攻击": ['select', 'union', 'if(', 'from', 'sleep(', 'information_', 'waitfor delay', ' or ', '||', '&&', ' and '], "命令/代码执行":['nslookup', 'wget', 'curl', 'whoami', '=id', '=echo', ';print('], "目录探测": [re.compile('/(.*?)/$'), re.compile("^\.(.*?)/$")], "路径穿越": [re.compile("\.\./(.*?)\w$"), re.compile("\.\.\(_\)(.*?)\w$"), re.compile("\./(.*?)\w$"), "file:///"]}
# 资产名称（后续在添加）
# assets_name_dict = {"phpmyadmin路径扫描": ['phpmyadmin', 'pma'], "WordPress路径扫描": ['wp']}

# 添加日志中白名单关键词，在做分析前请人工简单过下日志，添加状态码为200的白名单，除去过滤后缀的
# 或者先用脚本进行分析，然后正在添加，多次分析，输出最终分析结果
white_key_list = ['']

# 单秒请求次数阀值
second_threshold = 7

# 全局有效uri列表
global_runtime_eff_uri_list = []

# 将log日志中的时间转换为时间戳
def time2stamp(format_time):
    time_array = time.strptime(format_time, "%d/%m/%Y:%H:%M:%S")
    time_stamp = int(time.mktime(time_array))
    return time_stamp

# 将log日志但行内容转换为列表类型
def logFilter(log_text):
    log_text = log_text.strip()
    log_filter = []
    # 过滤规则
    ip_filter          = re.compile("([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}) - -")
    time_filter        = re.compile("\[(\w+/\w+/\w+:\w+:\w+:\w+) \+\d+\]")
    method_filter      = re.compile("\"([A-Za-z]{3,4}) ") # {3,4}代表只匹配GET/POST/MOVE/PUT/HEAD，如要匹配OPTION修改为{3,7}
    uri_filter         = re.compile("\"[A-Za-z]{3,7} (/.*?) HTTP/[\d]\.[\d]")
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
        time_stamp = int(time.mktime(time_array)) # 将输出的时间转换为时间戳，以便于计算
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

    if "Not find" not in log_filter:
        return log_filter
    else:
        return ""


# 过滤组合成新的分析日志
class Analyzer():

    def __init__(self, log_list):
        self.log_list = log_list

    def redPrint(self, info):
        print("\033[1;31m{}\033[0m".format(info))

    def cyanPrint(self, info):
        print("\033[1;36m{}\033[0m".format(info))

    def yellowPrint(self, info):
        print("\033[1;33m{}\033[0m".format(info))

    def greenPrint(self, info):
        print("\033[1;32m{}\033[0m".format(info))

    def magentaPrint(self, info):
        print("\033[1;35m{}\033[0m".format(info))

    def bluePrint(self, info):
        print("\033[1;34m{}\033[0m".format(info))

    # 将每个IP及其访问次数输出成字典
    def ipCountdict(self):
        ip_count_dict = {}
        for l in self.log_list:
            if l[0] not in ip_count_dict:
                ip_count_dict.update({l[0]: 1})
            elif l[0] in ip_count_dict:
                ip_count_dict[l[0]] += 1
        return ip_count_dict

    # 攻击TOP10 （暂时没用）
    def ipTop10(self, ip_count_dict):
        # 对IP字典根据其values值进行排序（从大到小）
        ip_count_sorted_list = sorted(ip_count_dict.items(), key=lambda x: (x[1], x[0]), reverse=True)
        ip_top_10 = ip_count_sorted_list[:10]
        return ip_top_10

    # 根据uri内容判断其漏洞名称
    # 通过百度搜索，然后在使用jieba分词进行判定
    def guessVuln(self, uri_info):
        global global_runtime_eff_uri_list
        if re.search("^/index\.[a-zA-Z]+$", uri_info):
            return ""
        if uri_info not in global_runtime_eff_uri_list:
            global_runtime_eff_uri_list.append(uri_info)
            # 白名单过滤，减少不必要输出
            for w in white_key_list:
                if w in uri_info:
                    return ""
            # 直接排除存在中文的
            if re.findall("=([\u4e00-\u9fff]+)", uri_info):
                return ""
            # 后缀判断
            for fd in uri_suffix_file_dict.items():
                for suffix in fd[1]:
                    if suffix in uri_info.lower() and "=" not in uri_info:
                        self.greenPrint("[*][{}][{}] 正在分析{}".format(time.strftime("%H:%M:%S", time.localtime()), fd[0], uri_info))
                        return fd[0]
            for vkwd in vuln_key_word_dict.items():
                for k in vkwd[1]:
                    if "re.Pattern" in str(type(k)):
                        if re.search(k, uri_info):
                            self.greenPrint("[*][{}][{}] 正在分析{}".format(time.strftime("%H:%M:%S", time.localtime()), vkwd[0], uri_info))
                            return vkwd[0]
                    else:
                        if k in uri_info.lower() and "=" in uri_info:
                            self.greenPrint("[*][{}][{}] 正在分析{}".format(time.strftime("%H:%M:%S", time.localtime()), vkwd[0], uri_info))
                            return vkwd[0]
            # 下面是采用百度搜索匹配关键词判断漏洞的
            time.sleep(random.uniform(0.1, 0.5)) # 加点延时，防止百度反爬
            headers = {
                "Host": "www.baidu.com",
                "User-Agent": random.choices(ua_list)[0],
                "Cookie": "BAIDUID=39B9CF98EE252213FE5549E5A950F198:FG=1; BIDUPSID=39B9CF98EE252213AD876D836CE567D2; PSTM=1606046190; COOKIE_SESSION=67_0_2_2_0_1_1_0_2_1_1_0_0_0_0_0_0_0_1617791571%7C2%230_0_1617791571%7C1; BAIDUID_BFESS=39B9CF98EE252213FE5549E5A950F198:FG=1; __yjs_duid=1_7796310f78e76819111f5df3ab5b86e01617791574519; BD_HOME=1; H_PS_PSSID=33986_33820_33848_33756_33607_33996; BD_UPN=123253; BA_HECTOR=84018g0125bl8080vv1g96ul00r; WWW_ST={}".format(int(time.time())),
            }
            # print(uri_info)
            vuln_search_str = ""
            # 百度搜索
            url = "https://www.baidu.com/s?ie=utf-8&mod=1&isbd=1&isid=df17aee20026f28d&ie=utf-8&f=8&rsv_bp=1&tn=baidu&wd="
            # self.greenPrint("[*][{}] 正在分析{}".format(time.strftime("%H:%M:%S", time.localtime()), uri_info))
            # uri_info = parse.quote(uri_info)
            req = requests.get(url+uri_info, headers=headers)
            # print(req.text)
            if req.status_code == 200:
                if "抱歉没有找到与" in req.text:
                    if "=" in uri_info:
                        uri_info = uri_info.split("=")[-1]
                        req = requests.get(url+uri_info, headers=headers)
                    else:
                        return ""
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
            # 进行百度搜索单页分词判断，根据筛选的词评率组合进行漏洞判断
            words_list = jieba.lcut(vuln_search_str)
            words_counts_dict = {}
            for w in words_list:
                if len(w) == 1:
                    continue
                else:
                    words_counts_dict[w] = words_counts_dict.get(w, 0) + 1
            words_items = list(words_counts_dict.items())
            words_items.sort(key=lambda x:x[1], reverse=True)
            # print(words_items)
            search_title_content = vuln_search_str.split("\n")
            vuln_name = ""
            cot = 0
            for t in search_title_content:
                # 判断单页搜索内容中前两个词均存在的title即为漏洞名称
                if len(words_list) > 1:
                    if words_list[0][0] in t and words_items[1][0] in t:
                        vuln_name = t
                        break
                    else:
                        cot += 1
                else:
                    cot += 1
            if cot > 0:
                vuln_name = search_title_content[0]
            # print(vuln_name)
            if vuln_name == "" and vuln_name == None and cot > 0 and len(vuln_name) <= 3:
                return ""
            for suffix_vu in vuln_key_word_filter:
                # print(vuln_name, suffix_vu)
                if suffix_vu in vuln_name:
                    vuln_name = vuln_name.split(suffix_vu)[0]
                    if len(vuln_name) > 3:
                        vuln_name += suffix_vu
                        self.greenPrint("[*][{}][{}] 正在分析{}".format(time.strftime("%H:%M:%S", time.localtime()), vuln_name, parse.unquote(uri_info)))
                        return vuln_name
                    else:
                        return ""
                else:
                    return ""
            # elif "后台" in vuln_name:
            #     vuln_name = vuln_name.split("后台")[0] + "后台"
            #     if len(vuln_name) >= 3:
            #         self.greenPrint("[*][{}][{}] 正在分析{}".format(time.strftime("%H:%M:%S", time.localtime()), vuln_name, parse.unquote(uri_info)))
            #         return vuln_name
            #     else:
            #         return ""
            # elif "管理" in vuln_name and ("系统" in vuln_name or "平台" in vuln_name):
            #     vuln_name = vuln_name.split("管理")[0] + "管理"
            #     if len(vuln_name) >= 3:
            #         self.greenPrint("[*][{}][{}] 正在分析{}".format(time.strftime("%H:%M:%S", time.localtime()), vuln_name, parse.unquote(uri_info)))
            #         return vuln_name
            #     else:
            #         return ""
            # elif "漏洞" in vuln_name:
            #     vuln_name = vuln_name.split("漏洞")[0] + "漏洞"
            #     if len(vuln_name) >= 3:
            #         self.greenPrint("[*][{}][{}] 正在分析{}".format(time.strftime("%H:%M:%S", time.localtime()), vuln_name, parse.unquote(uri_info)))
            #         return vuln_name
            #     else:
            #         return ""
            else:
                return ""
        else:
            return ""

    # 时间戳转日期
    def stamp2time(self, stamp_time):
        time_array = time.localtime(stamp_time)
        return time.strftime("%Y-%m-%d %H:%M:%S", time_array)

    # 去除攻击list中的重复项，并将uri请求次数添加到其中
    def newActList(self, ack_info_value, ip_uri_count_runtime_dict):
        new_ack_info_value = []
        runtime_uri_list = []
        for e in ack_info_value[0]:
            if e[2] not in runtime_uri_list:
                runtime_uri_list.append(e[2])
                e.append(ip_uri_count_runtime_dict.get(e[2]))
                new_ack_info_value.append(e)
        return new_ack_info_value

    # 分析
    def actAy(self):
        '''
        输出检查结果，目前是以IP和状态码及响应内容长度来进行判断，比较单一
        先简单输出，后续在考虑绘制图表，然后将分析结果输出为word或者html
        '''
        global start_time
        self.cyanPrint("[*] 正在进行分析中，请求耐心等待...")
        ip_count_dict = self.ipCountdict()
        time_runtime_dict = {}
        effective_uri_list = []
        runtime_vuln_name_dict = {}
        now_date = time.strftime("%Y_%m_%d", time.localtime())
        save_analyze_file_name = "access_log_analyze_{}.txt".format(now_date)
        with open(save_analyze_file_name, "w", encoding="utf-8") as f:
            for l in self.log_list:
                # 判断某时间段的多次请求
                if l[1] not in time_runtime_dict:
                    time_runtime_dict.update({l[1]: 1})
                if l[1] in time_runtime_dict:
                    time_runtime_dict[l[1]] += 1
                # print(time_runtime_dict.get(l[1]))
                if time_runtime_dict.get(l[1]) >= second_threshold: # 只看1s内请求大于7次及以上的
                    if int(l[-2]) == 200 and not re.search(uri_suffix_filter, l[-3]) and l[-3] != "/":
                        # print(l)
                        if l[-3] not in runtime_vuln_name_dict:
                            guess_vuln_name = self.guessVuln(l[-3])
                            if guess_vuln_name != "":
                                runtime_vuln_name_dict.update({l[-3]: guess_vuln_name})
                        l[1] = self.stamp2time(l[1])
                        # print(runtime_vuln_name_dict.get(l[-3]))
                        if runtime_vuln_name_dict.get(l[-3]) != "" or runtime_vuln_name_dict.get(l[-3]) != None:
                            l.append(runtime_vuln_name_dict.get(l[-3]))
                            effective_uri_list.append(l)

            runtime_ip_list = []
            attack_ip_list = []
            for eft_text in effective_uri_list:
                if eft_text[0] not in runtime_ip_list:
                    runtime_ip_list.append(eft_text[0])
                    attack_ip_list.append({eft_text[0]: [eft_text[1:]]})
                else:
                    attack_ip_list[runtime_ip_list.index(eft_text[0])].get(eft_text[0]).append(eft_text[1:])
            for ack_info in attack_ip_list:
                one_ip_uri_count_runtime_dict = {}
                ack_info_value = list(ack_info.values())
                for one_ip_ack_value in ack_info_value[0]:
                    if one_ip_ack_value[2] not in one_ip_uri_count_runtime_dict:
                        one_ip_uri_count_runtime_dict.update({one_ip_ack_value[2]: 1})
                    else:
                        one_ip_uri_count_runtime_dict[one_ip_ack_value[2]] = one_ip_uri_count_runtime_dict.get(one_ip_ack_value[2]) + 1

                new_act_list = self.newActList(ack_info_value, one_ip_uri_count_runtime_dict)
                attack_ip = list(ack_info.keys())[0]
                effective_attact_count = sum(one_ip_uri_count_runtime_dict.values())
                print("\033[34m-\033[0m"*50)
                f.write("-"*50+"\n")
                print("\033[31m[+] {}地址共请求{}次，服务器响应状态码为200的共{}次，具体内容如下：\033[0m".format(attack_ip, ip_count_dict.get(attack_ip), effective_attact_count))
                f.write("[+] {}地址共请求{}次，服务器响应状态码为200的共{}次，具体内容如下：\n".format(attack_ip, ip_count_dict.get(attack_ip), effective_attact_count))
                # 序号 请求时间 请求方式 状态码 响应内容长度 漏洞名称 URI/URL
                print("\033[35m{:>2}{:>6}{:>20}{:>5}{:>8}{:>8}{:>13}{:>11}\033[0m".format("序号", "请求时间", "请求方式", "状态码", "响应内容长度", "漏洞名称", "请求次数", "URI/URL"))
                f.write("{:>2}{:>6}{:>20}{:>5}{:>8}{:>8}{:>13}{:>11}\n".format("序号", "请求时间", "请求方式", "状态码", "响应内容长度", "漏洞名称", "请求次数", "URI/URL"))
                index_count = 0
                for p in new_act_list:
                    index_count += 1
                    # print(p[-2])
                    if p[-2] != "" and p[-2] != None:
                        vuln_name_len = len(p[-2])
                        print("\033[35m{0:>2}{1:>22}{2:>8}{3:>9}{4:>10}{5:>{8}}{6:>7}{7:>{9}}\033[0m".format(index_count, p[0], p[1], p[3], p[4], p[-2], p[-1], p[2], vuln_name_len+7, len(p[2])+5))
                        print("\033[35m{0:>2}{1:>22}{2:>8}{3:>9}{4:>10}{5:>{8}}{6:>7}{7:>{9}}\033[0m".format(index_count, p[0], p[1], p[3], p[4], p[-2], p[-1], p[2], vuln_name_len+7, len(p[2])+5))
                        f.write("{0:>2}{1:>22}{2:>8}{3:>9}{4:>10}{5:>{8}}{6:>7}{7:>{9}}\n".format(index_count, p[0], p[1], p[3], p[4], p[-2], p[-1], p[2], vuln_name_len+7, len(p[2])+5))
                    else:
                        if p[-2]  == None:
                            p[-2] = "无"
                        print("\033[35m{0:>2}{1:>22}{2:>8}{3:>9}{4:>10}{5:>{8}}{6:>7}{7:>{9}}\033[0m".format(index_count, p[0], p[1], p[3], p[4], p[-2], p[-1], p[2], 8, len(p[2])+5))
                        f.write("{0:>2}{1:>22}{2:>8}{3:>9}{4:>10}{5:>{8}}{6:>7}{7:>{9}}\n".format(index_count, p[0], p[1], p[3], p[4], p[-2], p[-1], p[2], 8, len(p[2])+5))

        end_time = time.time()
        use_time = int(end_time - start_time)
        if use_time > 60:
            min_time = use_time // 60
            second_time = use_time % 60
            self.greenPrint("[*] 分析完成，共用时{}分{}秒，结果已输出到脚本目录下，名称为{}".format(min_time, second_time, save_analyze_file_name))
        else:
            self.greenPrint("[*] 分析完成，共用时{}秒，结果已输出到脚本目录下，名称为{}".format(use_time, save_analyze_file_name))


if __name__ == '__main__':
    # 加载日志文件，目前是全部加载，大日志可能比较耗内存，后续在想怎么优化
    print("\033[036m[*][{}] 正在读取日志文件，请耐心等待...\033[0m".format(time.strftime("%H:%M:%S", time.localtime())))
    access_log_file = open("access.log", "r").readlines() #日志路径

    log_list = []
    for log_line in access_log_file:
        log_filter_line = logFilter(log_line)
        if log_filter_line != "":
            log_list.append(log_filter_line)
    print("\033[036m[*][{}] 文件读取完成，开始准备分析...\033[0m".format(time.strftime("%H:%M:%S", time.localtime())))
    a = Analyzer(log_list)
    a.actAy()


