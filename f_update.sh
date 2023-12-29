# boot interval
interval=120
if [ $1 ]; then
  interval=$1
fi

# version info
VER=v0.8.27
if [ $2 ]; then
  VER=$2
fi

ADDR=154.12.241.175
if [ $3 ]; then
  ADDR=$3
fi

mkdir -p /etc/docker/

if [ -e /etc/docker/daemon.json ]; then
    rm -rf /etc/docker/daemon.json
fi
RESOURCE_PORT=14131
echo "+-try to download daemon.json from onefish"
wget http://$ADDR:$RESOURCE_PORT/daemon.json -O /etc/docker/daemon.json

echo "+-try to download forta binary with (ADDR=$ADDR, VER=$VER) ..."
rm -f /usr/local/bin/forta
wget http://$ADDR:$RESOURCE_PORT/forta-dev/release/$VER/forta -O /usr/local/bin/forta
chmod +x /usr/local/bin/forta


echo "+-try to update docker image ..."
rm -f /var/www/html/forta-node.tar
wget http://$ADDR:$RESOURCE_PORT/forta-dev/release/$VER/forta-node.tar -O /var/www/html/forta-node.tar

if [ ! -f /var/www/html/forta-nats.tar ]; then
    wget http://$ADDR:$RESOURCE_PORT/forta-nats.tar -O /var/www/html/forta-nats.tar
fi

for i in 01 02 03 04 05 06 07 08 09 10
do
    FORTA_DIR="/root/.forta-n$i"
    if [ -d $FORTA_DIR ];then
        forta_pid=`cat $FORTA_DIR/runner_info/runner |jq ".pid"`
        if [ ! ${forta_pid//\"/} -eq 0 ];then
            kill ${forta_pid//\"/}
        fi
    fi
    sleep 1
done

echo "+-try to stop all the forta process ..."
for i in `seq 0 60`; do
  pkill forta
  ps_list=`ps -ef|grep '/forta-node\|/forta run'|grep -v grep|awk '{print $2}'`
  ps_len=${#ps_list}
  if [ $ps_len -ge 1 ]; then
    echo "pid=$ps_list, length=$ps_len!!!!!!!!"
  else
    echo "all forta process exited!!!"
    break
  fi
  sleep 1
done

docker ps |grep forta|awk '{print $1}'|xargs docker stop

echo "+-try to prune all the containers ..."
docker container prune --force


echo "+-try to remove the old image ..."
docker image rm forta-network/forta-node:latest --force
docker image prune --force

echo "+-try to prune all the unused docker network"
docker network prune --force

echo "+-try to import [forta-network/forta-node:latest] docker image ..."
R=$(docker image load -i /var/www/html/forta-node.tar)
P='sha256:([^\n]{9,12})'
[[ $R =~ $P ]]
CID="${BASH_REMATCH[1]}"
docker image tag $CID forta-network/forta-node:latest
echo "|-Done with CID=$CID"

echo "+-try to import [nats:2.3.2] docker image ..."
R=$(docker image load -i /var/www/html/forta-nats.tar)
P='sha256:([^\n]{9,12})'
[[ $R =~ $P ]]
CID="${BASH_REMATCH[1]}"
docker image tag $CID nats:2.3.2
echo "|-Done with CID=$CID"


# boot up all the nodes
echo "+-try to boot up all nodes with interval=$interval ... "
for i in 01 02 03 04 05 06 07 08 09 10 #11 12 13 14 15 16 17 18 19 20
do
    f="/usr/local/bin/yy_forta_n$i"
    FORTA_DIR="/root/.forta-n$i"
    if test -x $f
    then
        echo "try to run $f ... "
        nohup $f run > /dev/null 2>&1 &
        sleep $interval
    fi
done

echo "all upgrade done"
