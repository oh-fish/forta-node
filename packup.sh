#!/bin/bash
set -e
set -o pipefail

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

docker container prune -f

docker network prune -f

echo "--cleaning existing image ..."
img_num=`docker image ls |wc -l`
if [ $img_num -gt 1 ];then
    docker image ls|grep -v REPOSITORY|grep forta|awk '{print $3}'|xargs docker rmi
fi

echo "--removing existing forta binary ..."
if [ -e forta ]
then
    rm forta
fi

if [ -e /usr/local/bin/forta ]
then
    rm /usr/local/bin/forta
fi

echo "--building image forta-network/forta-node:latest ..."
NODE_IMAGE='forta-network/forta-node:latest'
docker build -t "$NODE_IMAGE" -f Dockerfile.node .

commitHash=0fba26d9b1ea5fe632ee41ba839437c810abde58
version=v0.8.26
RELEASE_DIR=/var/www/html/forta-dev/release/$version

if [ -e $RELEASE_DIR ]
then
    rm -rf $RELEASE_DIR
fi

mkdir -p $RELEASE_DIR

echo "--compiling forta binary -- $commitHash $version ..."
./scripts/build-for-fish.sh $commitHash $version

echo "--saving $NODE_IMAGE to disk ..."
cid=`docker image ls $NODE_IMAGE |grep forta-network/forta-node| awk '{print $3}'`
docker save $cid -o $RELEASE_DIR/forta-node.tar
cp -rf $PWD/forta $RELEASE_DIR/
cp -rf $PWD/forta /usr/local/bin
cp -rf f_update.sh /var/www/html/f_update.sh
echo "--Done."