# 日志分析
## WEB日志分析脚本
`access_log_analyze.py`脚本为nginx日志分析脚本，目前是一个初步版本，先留个档，后面在慢慢优化和更新。
`autoAnalyzeNginxLog.py`该脚本优化了些功能，目前是将结果输出成一个html的文件，该文件里面目前只有使用pyecharts绘制的图表，目前绘制的图表有：（图表中的数据主要是日志中状态码为200的）
- 攻击类型分布
- TOP10 IP分布
- 攻击IP地址全球地图分布
- TOP1攻击类型统计
- TOP1攻击有效次数统计（成功和失败，状态码200判断的）
- Webshell追踪（树状图）
Webshell追踪图：
![image](https://user-images.githubusercontent.com/42025843/124081694-7050a580-da7e-11eb-9698-1ec79b81fe73.png)
全球攻击地址分析图：
![image](https://user-images.githubusercontent.com/42025843/124081749-7d6d9480-da7e-11eb-8743-2b824867d4db.png)

## 流量分析脚本
后续更新
## 系统日志分析脚本
后续更新
