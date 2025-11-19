Port Scanner & Banner Identify From ，modified from the TXPortMap project.

[https://github.com/4dogs-cn/TXPortMap](https://github.com/4dogs-cn/TXPortMap)

1、Enhance compatibility for direct continuous IP scanning

As follows, all IP addresses from 172.16.110.10 to 172.16.110.14 will be scanned sequentially.

```bash
./TXPortMap -i 172.16.110.10-14 -t1000
```

2、Enhance domain name compatibility to prevent scenarios where certain ports only accept domain name access.

```bash
./TXPortMap -i example.com -t1000
```
