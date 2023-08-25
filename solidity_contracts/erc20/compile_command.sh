TARGET_FILE=$1
OPTION_FILE=$2
OUTPUT_TEMPLATE=$3

# Some note to the solidity compiling process:
# 1 Ubuntu RPM for solc is outdated. Therefore we choose solcjs so that we can easily keep the compiler up to date.
# 2 solcjs will start to generate PUSH0 after 0.8.20. We do not support this yet, so we have to specify EVM versions using standard-json inputs.
# 3 solcjs --starndard-json has some bugs (https://github.com/ethereum/solc-js/issues/460) so we can only use "content" as input.
# 4 To copy the source code into the json file, we have to escape \\ \" \t \n. (Ignore \b \r \f as we shouldn't have them in sol file)
BYTECODE=$(cat $TARGET_FILE \
| sed 's/$/\\n/' \
| tr -d '\n' \
| sed 's/\\/\\\\/g' \
| sed 's/\"/\\\"/g' \
| sed 's/\t/\\\t/g' \
| awk '{print "\"content\":\""$0"\""}' \
| sed -e '/__CONTRACT_CONTENT/{r /dev/stdin' -e 'd;}' $OPTION_FILE \
| solcjs -p --standard-json \
| grep -oP '\"object\":\"\K([^"]+)' 
)

sed "s/__CONTRACT_BYTECODE/$BYTECODE/g" $OUTPUT_TEMPLATE
