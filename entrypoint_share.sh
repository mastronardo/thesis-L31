#! /bash

sed -i "s/KEY/$KEY/g" /MultilevelSS/key.json
sed -i "s/SALT/$SALT/g" /MultilevelSS/salt.json

python3 /MultilevelSS/share.py -i info.json -s salt.json -k key.json -m $IPMONGO