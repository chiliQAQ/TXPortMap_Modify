Port Scanner & Banner Identify From ，对TXPortMap项目修改

[https://github.com/4dogs-cn/TXPortMap](https://github.com/4dogs-cn/TXPortMap)

1、增加直接对连续ip扫描的兼容方式

如下，会依次扫描172.16.110.10至172.16.110.14的所有ip地址

```bash
./TXPortMap -i 172.16.110.10-14 -t1000
```

2、增加对域名的兼容性，防止部分port只运行域名访问的情况

```bash
./TXPortMap -i example.com -t1000
```
