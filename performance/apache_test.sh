#!/bin/sh

TOTAL=0
TRIALS=10000

for i in $(eval echo "{1..$TRIALS}")
do
	START_TIME=$(date +%s%N)
	curl -s "http://localhost" > /dev/null
	END_TIME=$(date +%s%N)
	DELTA=`expr $END_TIME - $START_TIME`
	TOTAL=`expr $TOTAL + $DELTA`
	echo $DELTA "ns"
done

echo "Total: " $TOTAL " ns"
AVG=`expr $TOTAL / $TRIALS`
echo "Avg: " $AVG " ns"
