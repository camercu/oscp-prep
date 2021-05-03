#ip -br -4 addr show | grep -e eth0 -e tap | awk '{print "   " $1 ": " $3}' | cut -d/ -f1 | tr '\n' '  '
INTERFACES="eth0 tap0"
OUTPUT=""

for INT in $INTERFACES
do
        ADDRESS=`ip -br -4 addr show $INT 2>/dev/null | awk -F'[ \t/]+' '{print $3}' | grep -v '^$' || echo No Address`
        OUTPUT="$OUTPUT$INT: $ADDRESS | "
done
echo $OUTPUT | sed -e 's/ *| *$//'

