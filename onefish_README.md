根据代码库分析，这是一个名为 Forta 的区块链网络扫描节点项目。我将编写相应的项目文档。

# Forta Node

Forta 节点是一个 Docker 容器管理器,用于运行和管理多个服务和检测机器人(agents)来扫描区块链网络并生成警报。

## 主要功能

- 区块链网络扫描和监控
- 运行检测机器人(agents)进行威胁检测
- 生成和发布安全警报
- 支持多种区块链网络(通过配置chainId)
- 提供健康检查和指标监控
- IPFS存储支持

## 系统架构

Forta 节点由以下主要组件构成:

- Supervisor: 容器管理和监督服务
- Scanner: 区块链扫描服务
- Publisher: 警报发布服务
- Storage: IPFS存储服务
- Inspector: 系统检查服务
- JSON-RPC Proxy: JSON-RPC API代理服务

## 快速开始

### 依赖

1. [安装 Docker](https://docs.docker.com/get-docker/) 并启动 Docker 服务
2. [安装 Go](https://golang.org/doc/install)

### 本地开发依赖

#### 工具

- [Protobuf 编译器](https://grpc.io/docs/protoc-installation/)

#### Go 库

```shell
$ go install google.golang.org/grpc/cmd/protoc-gen-go-grpc 
$ go install github.com/golang/mock/mockgen@v1.5.0
```

### 构建和安装

#### 使用本地 Go 版本完整构建和安装

```shell
$ make install
```

#### 仅构建 CLI (使用本地 Go 版本)

```shell
$ go build -o forta .
```

### 运行节点

```shell
$ forta init  # 如果你还没有初始化和配置 Forta 目录
$ forta run
```

### 查看日志

CLI 日志通过 stdout 提供。其他节点服务和代理的日志可以通过以下方式查看:

```shell
$ docker ps  # 查看运行中的容器
$ docker logs -f <container_id>
```

### 停止

```
CTRL-C
```

## 配置

节点配置文件示例:

```yaml
# 要分析的网络的链ID (1=mainnet)
chainId: 1

# 用于检索被扫描链的区块和交易
scan:
  jsonRpc:
    url: <required>

# 用于检索区块中所有交易的跟踪
# 必须支持 trace_block (例如 Alchemy)
trace:
  jsonRpc:
    url: <required>

# 用于加载分配的机器人和检测新版本节点
registry:
  jsonRpc:
    url: <polygon-json-rpc-api>
```

## 安全

我们在 Immunefi 上有一个[漏洞赏金计划](https://immunefi.com/bounty/forta)。如果发现任何安全问题,请通过 Immunefi 仪表板报告,或联系 [tech@forta.org](mailto:tech@forta.org)。

## 许可证

该项目采用 MIT 许可证。

## 性能优化与稳定性指南

### 资源限制配置

1. Docker 容器资源限制
```yaml
# 在启动容器时添加资源限制
docker run -d \
  --name forta-node \
  --memory="4g" \
  --memory-swap="6g" \
  --cpus=2 \
  --restart=unless-stopped \
  forta-network/forta-node:latest
```

2. 日志轮转配置
```yaml
log:
  level: info
  maxLogSize: 50m  # 单个日志文件最大大小
  maxLogFiles: 10  # 保留的日志文件数量
```

### 内存优化

1. 配置区块扫描参数
```yaml
scan:
  blockRateLimit: 1000  # 限制区块扫描速率(毫秒)
  blockMaxAgeSeconds: 3600  # 限制扫描历史区块的时间范围
```

2. 批处理优化
```yaml
publisher:
  batchLimit: 500  # 单批次处理的最大警报数
  batchBufferSize: 100  # 批处理缓冲区大小
```

### 多实例部署

1. 配置不同的数据目录
```shell
# 实例1
$ FORTA_DIR=/data/forta1 forta init
$ FORTA_DIR=/data/forta1 forta run

# 实例2
$ FORTA_DIR=/data/forta2 forta init
$ FORTA_DIR=/data/forta2 forta run
```

2. 使用 Docker Compose 管理多实例
```yaml
version: '3'
services:
  forta-node-1:
    image: forta-network/forta-node:latest
    container_name: forta-node-1
    volumes:
      - /data/forta1:/app/forta
    environment:
      - FORTA_DIR=/app/forta
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 4G
    restart: unless-stopped

  forta-node-2:
    image: forta-network/forta-node:latest
    container_name: forta-node-2
    volumes:
      - /data/forta2:/app/forta
    environment:
      - FORTA_DIR=/app/forta
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 4G
    restart: unless-stopped
```

### 内存泄漏防护

1. 启用 IPFS 垃圾回收
```yaml
storage:
  ipfs:
    gcPeriod: 1h  # 每小时执行一次垃圾回收
```

2. 配置系统监控
```yaml
metrics:
  enabled: true
  port: 8089  # Prometheus 指标端口
```

3. 添加内存监控告警
```yaml
monitoring:
  memoryThreshold: 80  # 内存使用率超过80%时告警
  alertWebhook: "http://your-alert-system/webhook"
```

### 系统要求

- 推荐配置:
  - CPU: 4核心或更多
  - 内存: 8GB或更多
  - 磁盘: SSD，100GB以上
  - 网络: 稳定的互联网连接，建议带宽10Mbps以上

### 性能监控

1. 使用 Prometheus + Grafana 监控系统资源
2. 配置关键指标告警:
   - 内存使用率
   - CPU使用率
   - 磁盘使用率
   - 区块扫描延迟
   - API响应时间

## 部署打包指南

### 创建打包脚本

1. 创建 `packup.sh` 脚本:

```bash
#!/bin/bash

# 设置变量
VERSION="1.0.0"
BUILD_DIR="build"
DIST_DIR="dist"

# 创建必要的目录
mkdir -p $BUILD_DIR
mkdir -p $DIST_DIR

# 1. 编译项目
echo "Building Forta Node..."
make install

# 2. 准备配置文件
echo "Preparing config files..."
cat > $BUILD_DIR/config.yaml << EOF
chainId: 1
scan:
  jsonRpc:
    url: <your-rpc-url>
  blockRateLimit: 1000
  blockMaxAgeSeconds: 3600

trace:
  jsonRpc:
    url: <your-trace-url>

log:
  level: info
  maxLogSize: 50m
  maxLogFiles: 10

storage:
  ipfs:
    gcPeriod: 1h

metrics:
  enabled: true
  port: 8089
EOF

# 3. 准备 docker-compose 文件
echo "Preparing docker-compose file..."
cat > $BUILD_DIR/docker-compose.yml << EOF
version: '3'
services:
  forta-node:
    image: forta-network/forta-node:latest
    container_name: forta-node
    volumes:
      - ./forta:/app/forta
    environment:
      - FORTA_DIR=/app/forta
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 4G
    restart: unless-stopped
EOF

# 4. 准备启动脚本
echo "Preparing startup script..."
cat > $BUILD_DIR/start.sh << EOF
#!/bin/bash
set -e

# 初始化 Forta
forta init

# 复制配置文件
cp config.yaml ~/.forta/config.yaml

# 启动服务
docker-compose up -d
EOF
chmod +x $BUILD_DIR/start.sh

# 5. 打包
echo "Creating distribution package..."
cd $BUILD_DIR
tar -czf ../$DIST_DIR/forta-node-$VERSION.tar.gz *
cd ..

echo "Package created at $DIST_DIR/forta-node-$VERSION.tar.gz"
```

### 部署步骤

1. 执行打包脚本:
```bash
$ chmod +x packup.sh
$ ./packup.sh
```

2. 部署包内容:
```
forta-node-1.0.0.tar.gz
├── config.yaml        # 配置文件
├── docker-compose.yml # Docker 编排文件
└── start.sh          # 启动脚本
```

3. 在目标服务器上部署:
```bash
# 解压部署包
$ tar -xzf forta-node-1.0.0.tar.gz

# 修改配置
$ vim config.yaml  # 更新 RPC URL 等配置

# 启动服务
$ ./start.sh
```

### 多实例部署

1. 修改 docker-compose.yml 添加多个实例:
```yaml
version: '3'
services:
  forta-node-1:
    container_name: forta-node-1
    volumes:
      - ./forta1:/app/forta
    environment:
      - FORTA_DIR=/app/forta1
    # ... 其他配置

  forta-node-2:
    container_name: forta-node-2
    volumes:
      - ./forta2:/app/forta
    environment:
      - FORTA_DIR=/app/forta2
    # ... 其他配置
```

2. 为每个实例准备独立的配置:
```bash
$ cp config.yaml config-1.yaml
$ cp config.yaml config-2.yaml
# 修改每个配置文件的具体参数
```

3. 更新启动脚本:
```bash
#!/bin/bash
set -e

# 初始化实例1
FORTA_DIR=./forta1 forta init
cp config-1.yaml ./forta1/config.yaml

# 初始化实例2
FORTA_DIR=./forta2 forta init
cp config-2.yaml ./forta2/config.yaml

# 启动所有服务
docker-compose up -d
```

### 部署后验证

1. 检查服务状态:
```bash
$ docker-compose ps
$ docker logs forta-node-1
$ docker logs forta-node-2
```

2. 验证指标收集:
```bash
$ curl http://localhost:8089/metrics
```

3. 检查资源使用:
```bash
$ docker stats forta-node-1 forta-node-2
```
# packup.sh 脚本优化说明

我将修改 packup.sh 文件，添加资源限制和监控功能来解决这些问题：

```diff:packup.sh
#!/bin/bash

# 启用错误检查，脚本执行遇到错误时立即退出
set -e
# 启用管道错误检查，确保管道中的每个命令都执行成功
set -o pipefail

+ # 设置默认资源限制
+ MAX_MEMORY="4g"
+ MAX_CPU="2"
+ MEMORY_RESERVATION="3g"
+ MAX_MEMORY_SWAP="6g"
+ 
+ # 设置监控参数
+ MONITOR_INTERVAL=300  # 监控间隔(秒)
+ MEMORY_THRESHOLD=80   # 内存使用阈值(%)
+ CPU_THRESHOLD=90      # CPU使用阈值(%)
+ 
+ # 创建监控脚本
+ cat > monitor.sh << 'EOF'
+ #!/bin/bash
+ 
+ while true; do
+     # 获取所有 forta 容器的资源使用情况
+     containers=$(docker ps --filter "name=forta" --format "{{.Names}}")
+     
+     for container in $containers; do
+         # 获取容器的内存使用率
+         memory_usage=$(docker stats $container --no-stream --format "{{.MemPerc}}" | cut -d'%' -f1)
+         # 获取容器的 CPU 使用率
+         cpu_usage=$(docker stats $container --no-stream --format "{{.CPUPerc}}" | cut -d'%' -f1)
+         
+         # 检查资源使用是否超过阈值
+         if (( $(echo "$memory_usage > $MEMORY_THRESHOLD" | bc -l) )); then
+             echo "[$(date)] Warning: Container $container memory usage is high: ${memory_usage}%"
+             # 触发容器垃圾回收
+             docker exec $container sh -c "echo 1 > /proc/sys/vm/drop_caches"
+         fi
+         
+         if (( $(echo "$cpu_usage > $CPU_THRESHOLD" | bc -l) )); then
+             echo "[$(date)] Warning: Container $container CPU usage is high: ${cpu_usage}%"
+         fi
+     done
+     
+     sleep $MONITOR_INTERVAL
+ done
+ EOF
+ 
+ chmod +x monitor.sh

# 更新系统包并安装必要的依赖
apt-get -y upgrade && apt-get -y update
- apt-get -y install jq zip gcc
+ apt-get -y install jq zip gcc bc sysstat

[... 保持原有的依赖版本和清理代码不变 ...]

# 构建新的 forta 节点镜像
echo "--building image forta-network/forta-node:latest ..."
NODE_IMAGE='forta-network/forta-node:latest'
- docker build -t "$NODE_IMAGE" -f Dockerfile.node .
+ # 添加资源限制到 Docker 构建
+ docker build -t "$NODE_IMAGE" -f Dockerfile.node \
+   --build-arg MAX_MEMORY=$MAX_MEMORY \
+   --build-arg MAX_CPU=$MAX_CPU .

[... 保持版本设置代码不变 ...]

# 创建新的发布目录
mkdir -p $RELEASE_DIR

+ # 创建 Docker Compose 配置
+ cat > $RELEASE_DIR/docker-compose.yml << EOF
+ version: '3'
+ services:
+   forta-node-1:
+     image: $NODE_IMAGE
+     container_name: forta-node-1
+     restart: unless-stopped
+     deploy:
+       resources:
+         limits:
+           cpus: '$MAX_CPU'
+           memory: $MAX_MEMORY
+         reservations:
+           memory: $MEMORY_RESERVATION
+     environment:
+       - FORTA_DIR=/app/forta1
+     volumes:
+       - ./forta1:/app/forta1
+     logging:
+       driver: "json-file"
+       options:
+         max-size: "200m"
+         max-file: "3"
+     ulimits:
+       nofile:
+         soft: 65536
+         hard: 65536
+ 
+   forta-node-2:
+     image: $NODE_IMAGE
+     container_name: forta-node-2
+     restart: unless-stopped
+     deploy:
+       resources:
+         limits:
+           cpus: '$MAX_CPU'
+           memory: $MAX_MEMORY
+         reservations:
+           memory: $MEMORY_RESERVATION
+     environment:
+       - FORTA_DIR=/app/forta2
+     volumes:
+       - ./forta2:/app/forta2
+     logging:
+       driver: "json-file"
+       options:
+         max-size: "200m"
+         max-file: "3"
+     ulimits:
+       nofile:
+         soft: 65536
+         hard: 65536
+ EOF

# 编译 forta 二进制文件
echo "--compiling forta binary -- $commitHash $version ..."
./scripts/build-for-fish.sh $commitHash $version

[... 保持文件复制代码不变 ...]

+ # 创建启动脚本
+ cat > $RELEASE_DIR/start.sh << 'EOF'
+ #!/bin/bash
+ 
+ # 启动监控
+ ./monitor.sh &
+ 
+ # 启动 Docker Compose
+ docker-compose up -d
+ 
+ # 等待容器启动
+ sleep 10
+ 
+ # 启用系统调优
+ for container in $(docker ps --filter "name=forta" --format "{{.Names}}"); do
+     # 设置容器内存管理
+     docker exec $container sh -c "echo 1 > /proc/sys/vm/drop_caches"
+     docker exec $container sh -c "echo 3 > /proc/sys/vm/drop_caches"
+     docker exec $container sh -c "echo 1 > /proc/sys/vm/compact_memory"
+     
+     # 设置容器 IO 优先级
+     docker update --cpu-shares 1024 $container
+ done
+ EOF
+ 
+ chmod +x $RELEASE_DIR/start.sh

echo "--Done."
```

主要优化内容：

1. 资源限制：
- 设置内存和 CPU 限制
- 添加内存预留
- 配置内存交换限制
- 设置文件描述符限制

2. 监控和自动恢复：
- 添加资源监控脚本
- 设置内存和 CPU 使用阈值
- 自动触发内存回收
- 记录资源使用警告

3. 系统优化：
- 配置日志轮转
- 优化容器 IO 优先级
- 启用系统内存管理
- 设置容器重启策略

4. 多实例支持：
- 使用 Docker Compose 管理多个实例
- 为每个实例配置独立的存储卷
- 独立的资源限制

使用方法：
1. 运行 packup.sh 生成部署包
2. 在目标服务器上解压部署包
3. 修改配置文件（如需要）
4. 运行 start.sh 启动服务

这些修改应该能够：
1. 防止服务器负载过高
2. 解决内存溢出问题
3. 支持多实例部署
4. 实现长期稳定运行
