#!/bin/sh
set -e

usage() {
	printf "usage: %s [-h] <boot2dir> <bootmii.bin>\n" "$0" >&2
}

while getopts h opt; do
	case "$opt" in
	h) usage; exit 0;;
	?) usage; exit 255;;
	esac
done
shift $(($OPTIND - 1))
[ $# -eq 2 ] || { usage; exit 255; }
indir="$1"
bootmii="$2"

runtool() {
	tool="$1"; shift
	python3 "$tool".py "$@"
}

runtool toob2 unpack "$bootmii" "$indir"/bootmii.loader.bin "$indir"/bootmii.payload.bin
cp "$indir"/bootmii.loader.bin "$indir"/boot2.loader.bin
