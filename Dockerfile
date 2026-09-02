# 开发镜像：Python + z3-solver，用来跑不依赖香山精化的检查。
# 原因：公开仓库需要一个可启动的环境说明，但不能假装「Docker 里已经复现过
# CSR 子模块精化」。yosys 0.68 / firtool 1.135.0 没有稳定的发行版 apt 包，
# 精化仍须宿主机或 xs-env 里已装好的工具 + 一份 mill 编过的香山树。
FROM python:3.12-slim

WORKDIR /opt/csrformal

# 不装 gh：解析分支名 / demo-spec-drift.sh 对照 main 时请在宿主机跑，
# 或给脚本传 40 位 sha。装 gh 会把镜像撑大，层 1 检查（lint 钉死 sha）只用 curl。
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        git \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# 层 1：语法 / 规格自洽。不要在这里跑 `check CSRPermitModule`。
CMD ["python3", "-m", "compileall", "-q", "csrformal"]
