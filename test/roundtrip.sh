#!/bin/bash
# Round-trip test: run Snort with the abc DAQ and log_abc logger on each .abc
# file, compare output to ref/<name>.rt.abc.
#
# Usage: roundtrip.sh <snort> <daq_dir> <logger_so>
#   or set env vars: SNORT, DAQ_DIR, LOGGER_SO

TOP="."
[ "$srcdir" ] && TOP=$srcdir

SNORT="${1:-${SNORT:-}}"
DAQ_DIR="${2:-${DAQ_DIR:-}}"
LOGGER_SO="${3:-${LOGGER_SO:-}}"

if [ -z "$SNORT" ] || [ -z "$DAQ_DIR" ] || [ -z "$LOGGER_SO" ]; then
    echo "Usage: $0 <snort> <daq_dir> <logger_so>"
    echo "  or set SNORT, DAQ_DIR, LOGGER_SO env vars"
    exit 1
fi

TMP=tmp/roundtrip
rm -rf $TMP
mkdir -p $TMP
[[ -d ref/ ]] || mkdir ref

pass=0
fail=0
bad=""

for fin in "$TOP"/*.abc; do
    name="${fin%.abc}"
    name="${name##*/}"

    echo -n "Round-trip $name: "

    out="$TMP/$name.rt.abc"
    ref="ref/$name.rt.abc"
    ref_src="$TOP/ref/$name.rt.abc"

    "$SNORT" \
        --plugin-path "$LOGGER_SO" \
        -L log_abc \
        --daq-dir "$DAQ_DIR" \
        --daq abc \
        -r "$fin" \
        -q > "$out" 2>/dev/null

    [ -f "$ref_src" ] && cp "$ref_src" "$ref"

    if [ ! -f "$ref" ]; then
        cp "$out" "$ref"
        echo "REF (created)"
        pass=$((pass+1))
        continue
    fi

    if diff -q "$ref" "$out" &>/dev/null; then
        echo OK
        pass=$((pass+1))
    else
        echo FAIL
        diff "$ref" "$out"
        fail=$((fail+1))
        bad+="$name "
    fi
done

echo "Round-trip: Pass=$pass, Fail=$fail"
[ $fail -gt 0 ] && echo "Failures = $bad" && exit 1
exit 0
