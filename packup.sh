#!/bin/bash
set -e
set -o pipefail
apt-get -y upgrade && apt-get -y update
apt-get -y install jq zip gcc

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
FORTA_CORE_GO_VERSION=github.com/forta-network/forta-core-go@v0.0.0-20240401084734-5e73299ce04c
ONEFISH_FORTA_CORE_GO_VERSION=github.com/oh-fish/forta-core-go@v0.1.2
go mod edit -replace=${FORTA_CORE_GO_VERSION}=${ONEFISH_FORTA_CORE_GO_VERSION}
go mod tidy

echo "--cleaning existing containers..."
docker container prune -f
echo "--cleaning existing docker network ..."
docker network prune -f

echo "--cleaning existing image ..."
img_num=`docker image ls|grep -v REPOSITORY|grep forta|awk '{print $3}'| wc -l`
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

#commitHash=83ec187ba03628cd245aac67974d830343ac707e
#version=v0.8.28
#commitHash=41ebf86ac0b189de87ae7862dfbd4b72376e42cc
#version=v0.8.29
#commitHash=82f4e312413d82dedfd3f6ca83c1ee8cf592e33e
#version=v0.9.0
#commitHash=45dcd3bbb43f63614589a5180b2b4ef248e840c0
#version=v0.9.1
# commitHash=c097d7fb3eef36dfb4d0620570b3913d61e82c04
# version=v0.9.2
# commitHash=b067fd8d58cd71e043a199fc06a1d43c22609ee7
# version=v0.9.3
# commitHash=6b60b3649e57d1ff39b6968cd39f1bc222d4d740
# version=v0.9.4
# commitHash=c3c29f897c45c1020d9c28702ffdae08feea3c44
# version=v0.9.5
# commitHash=f1cd717364b8d069fd865af25ce25e2f675fac87
# version=v0.9.6
# commitHash=d913ff8febbb4edc04e050e4cc671cb6b005f3e2
# version=v0.9.7

commitHash=a32908762859a5a4d4e033e6f4ad7107c2da72c8
version=v0.9.8
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
cp -rf daemon.json /var/www/html/daemon.json
echo "--Done."
