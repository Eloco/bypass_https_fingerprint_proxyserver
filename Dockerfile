# 使用官方Python基础镜像
FROM python:3.9-slim

# 设置工作目录
WORKDIR /app

# 将 requirements.txt 文件复制到容器中
COPY requirements.txt /app/

# 安装 Python 依赖项
RUN pip install --no-cache-dir -r requirements.txt

# 复制 Python 脚本和证书文件到容器中
COPY main.py /app/
COPY proxy.crt /app/
COPY proxy.key /app/

# 暴露端口
EXPOSE 8088

# 设置默认启动命令
CMD ["python", "main.py"]
