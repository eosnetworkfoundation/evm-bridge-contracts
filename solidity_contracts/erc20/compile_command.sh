cat $1 \
| sed 's/$/\\n/' \
| tr -d '\n' |sed 's/\"/\\\"/g' \
| awk '{print "\"content\":\""$0"\""}' \
| sed -e '/CONTRACT_CONTENT/{r /dev/stdin' -e 'd;}' $2 \
| solcjs -p --standard-json \
| grep -oP '\"object\":\K(\"[^"]+\")' \
| awk '{print "constexpr char bytecode[] = "$0";"}'