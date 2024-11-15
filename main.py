#!/usr/bin/env pythonresponse.texe
# coding=utf-8

import http.server
import socketserver
from urllib.parse import urlparse
from curl_cffi import requests
import random
import ssl

class ProxyHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.forward_request()

    def do_POST(self):
        self.forward_request()

    def do_PUT(self):
        self.forward_request()

    def do_DELETE(self):
        self.forward_request()

    def do_CONNECT(self):
        host, port = self.path.split(":")
        port = int(port)
        self.send_response(200, "Connection Established")
        self.end_headers()

        # 与客户端建立SSL连接，使用自签名证书
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile="proxy.crt", keyfile="proxy.key")
        client_ssl_sock = context.wrap_socket(
            self.connection,
            server_side=True
        )
        # 使用 _transfer_data 来转发解密后的数据
        self._transfer_data(client_ssl_sock)


    def _transfer_data(self, client_ssl_sock):
        while True:
            # 从客户端读取解密数据
            data_from_client = client_ssl_sock.recv(4096)
            if not data_from_client:
                break
            # print(f"Decrypted data from client: {data_from_client.decode('utf-8', errors='ignore')}")
            if b"\r\n\r\n" in data_from_client: # 检查请求是否已结束（检查 "\r\n\r\n"）
                break

        request_string = data_from_client.decode('utf-8')
        # 分割报文的行
        method, url, http_version, headers, body = parse_http_request(request_string)

        response=self._parse_and_forward_request(method,url,headers,body)
        self.send_response_to_client(client_ssl_sock,response)

    def send_response_to_client(self,client_ssl_sock, response):
        decoded_body = response.content
        status_line = f"HTTP/1.1 {response.status_code} {response.reason}\r\n"
        headers = "".join(
            f"{k}: {v}\r\n"
            for k, v in response.headers.items()
            if ("-encoding" not in k.lower()) 
        )
        headers += f"Content-Length: {len(decoded_body)}\r\n"
        # 拼接完整的响应
        full_response = status_line + headers + "\r\n"
        full_response = full_response.encode() + decoded_body
        # 发送到客户端
        client_ssl_sock.sendall(full_response)


    def _parse_and_forward_request(self, method, url , headers, data):
        """解析客户端请求的 HTTP 方法和 URL 并转发"""
        try:
            # 将请求内容解码为字符串

            proxy = {
                "http": "127.0.0.1:7890",
                "https": "127.0.0.1:7890"
            }

            headers=dict(headers)
            if 'User-Agent' in headers:
                if "Mozilla" not in headers["User-Agent"]:
                    headers["User-Agent"]="Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:129.0) Gecko/20100101 Firefox/129.0"

            browsers = [
                "chrome99", "chrome100", "chrome101", "chrome104", "chrome107", 
                "chrome110", "chrome116", "chrome119", "chrome120", "chrome123", 
                "chrome124", "chrome99_android", "edge99", "edge101", "safari15_3", 
                "safari15_5", "safari17_0", "safari17_2_ios", "safari18_0", "safari18_0_ios"
            ]
            # 随机选择一个元素
            random_browser = random.choice(browsers)

            # 使用上游代理发起请求
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                data=data,
                proxies=proxy,  # 设置代理
                impersonate=random_browser,
            )
            return response


        except Exception as e:
            print(f"Error parsing and forwarding request: {e}")
            self.send_error(500, f"Proxy error: {e}")


    def _get_content_length(self, headers):
        """从请求头中提取 Content-Length"""
        for line in headers.split("\r\n"):
            if line.lower().startswith("content-length"):
                return int(line.split(":")[1].strip())
        return None

    def forward_request(self):
        url = self.path
        parsed_url = urlparse(url)
        self.path = parsed_url.path

        # 构建完整的请求 URL
        full_url = f"{parsed_url.scheme}://{parsed_url.netloc}{self.path}"

        # 转发请求到目标 URL
        req_headers = self.headers
        req_data = None
        if self.command in ["POST", "PUT"]:
            content_length = int(self.headers.get('Content-Length', 0))
            req_data = self.rfile.read(content_length) if content_length > 0 else None

        response=self._parse_and_forward_request(self.command,full_url,req_headers,req_data)
        self.send_response(response.status_code)
        # print(response.text)
        # 重新计算内容长度并设置 'Content-Length' 头部
        content_length = len(response.content)
        self.send_header("Content-Length", str(content_length))
        # 设置其他头部
        for header, value in response.headers.items():
            if "-encoding" in header.lower():  # 避免重复设置
                pass
            elif header.lower() != "content-length":  # 避免重复设置
                self.send_header(header, value)
        self.end_headers()
        self.wfile.write(response.content)

class ThreadedTCPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """支持多线程的HTTP服务器"""
    daemon_threads = True
    allow_reuse_address = True

def parse_http_request(request_string):
    parser = HTTPParser()
    parser.feed(request_string)
    return parser.get_headers(), parser.get_method(), parser.get_url()

def parse_http_request(request_string):
    # 分割报文字符串为多行
    lines = request_string.strip().splitlines()
    # 请求行 (Method, URL, HTTP version)
    request_line = lines[0].split()
    method = request_line[0]  # GET or POST
    url = request_line[1]  # Path (e.g., "/index.html")
    http_version = request_line[2]  # HTTP/1.1
    # 解析请求头
    headers = {}
    body = None  # 请求体内容 (POST 请求有 body)
    # 查找请求头和请求体
    is_header_done = False
    for line in lines[1:]:
        if line == "":
            is_header_done = True
            continue  # 空行表示请求头结束，开始请求体
        if not is_header_done:
            # 解析请求头
            header_key, header_value = line.split(":", 1)
            headers[header_key.strip()] = header_value.strip()
        else:
            # 如果是 POST 请求，body 通常会跟在头部之后
            if body is None:
                body = line  # 请求体部分（例如 POST 数据）
    # 解析完整的 URL (假设请求报文是标准的 http://host/path)
    if 'Host' in headers:
        host = headers['Host']
        full_url = f"https://{host}{url}"
    else:
        full_url = url  # 没有 Host 头时，仅返回路径
    return method, full_url, http_version, headers, body

if __name__ == "__main__":
    port = 8088
    server_address = ('', port)
    httpd = ThreadedTCPServer(server_address, ProxyHTTPRequestHandler)
    print(f"Serving on port {port}...")
    httpd.serve_forever()

