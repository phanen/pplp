# gps
## NMEA 协议
```
例：$GPRMC,024813.640,A,3158.4608,N,11848.3737,E,10.05,324.27,150706,,,A*50
字段0：$GPRMC，语句ID，表明该语句为Recommended Minimum Specific GPS/TRANSIT Data（RMC）推荐最小定位信息
字段1：UTC时间，hhmmss.sss格式
字段2：状态，A=定位，V=未定位
字段3：纬度ddmm.mmmm，度分格式（前导位数不足则补0）
字段4：纬度N（北纬）或S（南纬）
字段5：经度dddmm.mmmm，度分格式（前导位数不足则补0）
字段6：经度E（东经）或W（西经）
字段7：速度，节，Knots
字段8：方位角，度
字段9：UTC日期，DDMMYY格式
字段10：磁偏角，（000 - 180）度（前导位数不足则补0）
字段11：磁偏角方向，E=东W=西
字段12：模式，A=自动，D=差分，E=估测，N=数据无效（3.0协议内容）
字段13：校验值（$与*之间的数异或后的值）
```

## pymea2

```
text = "$GNRMC,074733.00,A,2241.28818,N,11358.44210,E,3.866,,070720,,,A*60"
msg = pynmea2.parse(text)

msg
Out[6]: <RMC(timestamp=datetime.time(7, 47, 33), status='A', lat='2241.28818', lat_dir='N', lon='11358.44210', lon_dir='E', spd_over_grnd=3.866, true_course=None, datestamp=datetime.date(2020, 7, 7), mag_variation='', mag_var_dir='') data=['A']>
# msg.latitude
# msg.longitude
```
* [Quickstart — Folium 0.12.1 documentation (python-visualization.github.io)](https://python-visualization.github.io/folium/quickstart.html)
* [serial/serial_example.cc at main · wjwwood/serial (github.com)](https://github.com/wjwwood/serial/blob/main/examples/serial_example.cc)
* [4G网络有公网ip地址么](https://www.zhihu.com/question/275807447)
