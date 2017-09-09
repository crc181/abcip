#!/bin/bash

TMP=tmp
TOP="."

[ "$srcdir" ] && TOP=$srcdir

pass=0
fail=0
bad=""

rm -rf $TMP/
mkdir $TMP/
[[ -d ref/ ]] || mkdir ref

cp $TOP/data.* $TMP/

for fin in $TOP/*.abc ; do
    abc=${fin%.abc}
    abc=${abc##*/}

    fout=$abc.out
    pcap=$abc.pcap

    echo -n "Testing $abc: "

    ../src/app/abcip --pcap $TMP/$pcap < $fin &> /dev/null &&
        tcpdump -tvnnXXr $TMP/$pcap > $TMP/$fout 2> /dev/null

    tcpdump -tvnnXXr $TOP/ref/$pcap > ref/$fout 2> /dev/null

    if diff -q ref/$fout $TMP/$fout ; then
        echo OK 
        pass=$((pass+1))
    else
        fail=$((fail+1))
        bad+="$abc "
    fi
done

echo "Pass=$pass, Fail=$fail"

if [ $fail -gt 0 ] ; then
    echo "Failures = $bad"
    exit -1
fi

