#!/bin/bash

# 启用错误检查，脚本执行遇到错误时立即退出
set -e
# 启用管道错误检查，确保管道中的每个命令都执行成功
set -o pipefail

# 设置默认资源限制
MAX_MEMORY="4g"
MAX_CPU="2"
MEMORY_RESERVATION="3g"
MAX_MEMORY_SWAP="6g"

# 设置监控参数
MONITOR_INTERVAL=300  # 监控间隔(秒)
MEMORY_THRESHOLD=80   # 内存使用阈值(%)
CPU_THRESHOLD=90      # CPU使用阈值(%)

# 创建监控脚本
cat > monitor.sh << 'EOF'
#!/bin/bash

while true; do
    # 获取所有 forta 容器的资源使用情况
    containers=$(docker ps --filter "name=forta" --format "{{.Names}}")
    
    for container in $containers; do
        # 获取容器的内存使用率
        memory_usage=$(docker stats $container --no-stream --format "{{.MemPerc}}" | cut -d'%' -f1)
        # 获取容器的 CPU 使用率
        cpu_usage=$(docker stats $container --no-stream --format "{{.CPUPerc}}" | cut -d'%' -f1)
        
        # 检查资源使用是否超过阈值
        if (( $(echo "$memory_usage > $MEMORY_THRESHOLD" | bc -l) )); then
            echo "[$(date)] Warning: Container $container memory usage is high: ${memory_usage}%"
            # 触发容器垃圾回收
            docker exec $container sh -c "echo 1 > /proc/sys/vm/drop_caches"
        fi
        
        if (( $(echo "$cpu_usage > $CPU_THRESHOLD" | bc -l) )); then
            echo "[$(date)] Warning: Container $container CPU usage is high: ${cpu_usage}%"
        fi
    done
    
    sleep $MONITOR_INTERVAL
done
EOF

chmod +x monitor.sh

# 更新系统包并安装必要的依赖
apt-get -y upgrade && apt-get -y update
apt-get -y install jq zip gcc bc sysstat

# 以下注释代码用于停止所有运行中的 forta 进程
# 每秒检查一次，最多检查60次
#echo "+-try to stop all the forta process ..."
#for i in `seq 0 60`
#do
#  pkill forta
#  ps_list=`ps -ef|grep '/forta-node\|/forta run'|grep -v grep|awk '{print $2}'`
#  ps_len=${#ps_list}
#  if [ $ps_len -ge 1 ]; then
#    echo "pid=$ps_list, length=$ps_len!!!!!!!!"
#  else
#    echo "all forta process exited!!!"
#    break
#  fi
#  sleep 1
#done

# 定义依赖版本
# 原始 forta-core-go 版本
FORTA_CORE_GO_VERSION=github.com/forta-network/forta-core-go@v0.0.0-20240423071831-edccde967e5b
# 自定义 forta-core-go 版本
ONEFISH_FORTA_CORE_GO_VERSION=github.com/oh-fish/forta-core-go@v0.1.4
# 替换依赖版本并更新 go.mod
go mod edit -replace=${FORTA_CORE_GO_VERSION}=${ONEFISH_FORTA_CORE_GO_VERSION}
go mod tidy

# 清理 Docker 环境
echo "--cleaning existing containers..."
docker container prune -f  # 删除所有停止的容器
echo "--cleaning existing docker network ..."
docker network prune -f    # 删除所有未使用的网络

# 清理现有的 forta 镜像
echo "--cleaning existing image ..."
img_num=`docker image ls|grep -v REPOSITORY|grep forta|awk '{print $3}'| wc -l`
if [ $img_num -gt 1 ];then
    docker image ls|grep -v REPOSITORY|grep forta|awk '{print $3}'|xargs docker rmi
fi

# 删除现有的 forta 二进制文件
echo "--removing existing forta binary ..."
if [ -e forta ]
then
    rm forta
fi

if [ -e /usr/local/bin/forta ]
then
    rm /usr/local/bin/forta
fi

# 构建新的 forta 节点镜像
echo "--building image forta-network/forta-node:latest ..."
NODE_IMAGE='forta-network/forta-node:latest'
docker build -t "$NODE_IMAGE" -f Dockerfile.node \
  --build-arg MAX_MEMORY=$MAX_MEMORY \
  --build-arg MAX_CPU=$MAX_CPU .

# 版本历史记录（已注释）
#commitHash=83ec187ba03628cd245aac67974d830343ac707e
#version=v0.8.28
# ... 其他历史版本 ...

# 当前使用的版本
commitHash=cdfee8a229514ab683c7ba31096d1f8b0c1ddc4c
version=v0.9.10

# 设置发布目录
RELEASE_DIR=/var/www/html/forta-dev/release/$version

# 如果发布目录存在则删除
if [ -e $RELEASE_DIR ]
then
    rm -rf $RELEASE_DIR
fi

# 创建新的发布目录
mkdir -p $RELEASE_DIR

# 创建 Docker Compose 配置
cat > $RELEASE_DIR/docker-compose.yml << EOF
version: '3'
services:
  forta-node-1:
    image: $NODE_IMAGE
    container_name: forta-node-1
    restart: unless-stopped
    deploy:
      resources:
        limits:
          cpus: '$MAX_CPU'
          memory: $MAX_MEMORY
        reservations:
          memory: $MEMORY_RESERVATION
    environment:
      - FORTA_DIR=/app/forta1
    volumes:
      - ./forta1:/app/forta1
    logging:
      driver: "json-file"
      options:
        max-size: "200m"
        max-file: "3"
    ulimits:
      nofile:
        soft: 65536
        hard: 65536

  forta-node-2:
    image: $NODE_IMAGE
    container_name: forta-node-2
    restart: unless-stopped
    deploy:
      resources:
        limits:
          cpus: '$MAX_CPU'
          memory: $MAX_MEMORY
        reservations:
          memory: $MEMORY_RESERVATION
    environment:
      - FORTA_DIR=/app/forta2
    volumes:
      - ./forta2:/app/forta2
    logging:
      driver: "json-file"
      options:
        max-size: "200m"
        max-file: "3"
    ulimits:
      nofile:
        soft: 65536
        hard: 65536
EOF

# 编译 forta 二进制文件
echo "--compiling forta binary -- $commitHash $version ..."
./scripts/build-for-fish.sh $commitHash $version

# 保存 Docker 镜像到磁盘
echo "--saving $NODE_IMAGE to disk ..."
cid=`docker image ls $NODE_IMAGE |grep forta-network/forta-node| awk '{print $3}'`
docker save $cid -o $RELEASE_DIR/forta-node.tar

# 复制必要的文件到目标位置
cp -rf $PWD/forta $RELEASE_DIR/           # 复制二进制文件到发布目录
cp -rf $PWD/forta /usr/local/bin          # 复制二进制文件到系统 PATH
cp -rf f_update.sh /var/www/html/f_update.sh  # 复制更新脚本
cp -rf daemon.json /var/www/html/daemon.json  # 复制 daemon 配置文件

# 创建启动脚本
cat > $RELEASE_DIR/start.sh << 'EOF'
#!/bin/bash

# 启动监控
./monitor.sh &

# 启动 Docker Compose
docker-compose up -d

# 等待容器启动
sleep 10

# 启用系统调优
for container in $(docker ps --filter "name=forta" --format "{{.Names}}"); do
    # 设置容器内存管理
    docker exec $container sh -c "echo 1 > /proc/sys/vm/drop_caches"
    docker exec $container sh -c "echo 3 > /proc/sys/vm/drop_caches"
    docker exec $container sh -c "echo 1 > /proc/sys/vm/compact_memory"
    
    # 设置容器 IO 优先级
    docker update --cpu-shares 1024 $container
done
EOF

chmod +x $RELEASE_DIR/start.sh

echo "--Done."
