for name in $(ifconfig -a | sed 's/[ \t].*//;/^\(lo\|\)$/d' | grep veth)
do
    echo $name
    ip link delete $name # uncomment this
done

ip link
