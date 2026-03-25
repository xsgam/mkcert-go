# MKCert-go

MKCert-go 是一款用go语言开发的证书签名工具，用于制作本地可信开发证书。

## 用法

- MKCert.exe -newca
 
    在当前目录下创建一个CA证书,cert和key分别保存为rootCA.pem、rootCA.key，比如已经存在则提示已经创建; 证书的有效期默认是10年;

- MKCert.exe -ca [CA-path]

    提取rootCA.pem的证书信息，包含名称、指纹、创建时间、过期时间

- MKCert.exe -days [1000] -host [www.example.com]

    为主机名www.example.com创建一个证书, 在当前目录下生成key文件和cert文件，用rootCA为它签名，有效期默认是1000天；
    当主机名为*时，生成_wildcard前缀，避免无法保存文件，例如_wildcard.example.com.crt

    支持如下主机名：
    - "example.com"
    - "*.example.com"
    - "localhost"

- mkcert.exe -cert [cert-path]

    获取cert-path证书的信息，包含名称、指纹、创建时间、过期时间

## 命令示例

```
MKCert.exe -newca
MKCert.exe -ca [CA-path]
mkcert.exe -days 1000 -host *.example.com
mkcert.exe -days 1000 -host www.example.com
mkcert.exe -cert [cert-path]
```
