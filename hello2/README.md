```
go generate
go run -exec sudo . lo
dig -p 2152 +tcp +short @127.0.0.53 google.com

2024/10/07 00:42:39 Map contents:
2024/10/07 00:42:40 Map contents:
        127.0.0.1 => 3
2024/10/07 00:42:41 Map contents:
        127.0.0.1 => 3
```