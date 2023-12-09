#!/bin/sh
set -e

usage() {
	printf "usage: %s [-h] [-b] [-p PROFILE] <nandfile> <outdir>\n" "$0" >&2
}

profile=retail
backup=

while getopts hbp: opt; do
	case "$opt" in
	b) backup=1;;
	h) usage; exit 0;;
	p) profile="$OPTARG";;
	?) usage; exit 255;;
	esac
done
shift $(($OPTIND - 1))
[ $# -eq 2 ] || { usage; exit 255; }
nandfile="$1"
outdir="$2"

case "$profile" in
retail|*-retail)
	tmd_chain=Root-CA00000001-CP00000004
	tik_chain=Root-CA00000001-XS00000003
	;;
dev|*-dev)
	tmd_chain=Root-CA00000002-CP00000007
	tik_chain=Root-CA00000002-XS00000006
	;;
*)	printf "%s: unknown profile %s\n" "$0" "$profile" >&2; exit 255;;
esac

runtool() {
	tool="$1"; shift
	python3 "$tool".py "$@"
}

nandfile="$1"
outdir="$2"

echo ">> extract"
runtool tsoprocky -p "$profile" extract-boot2 ${backup:+-b} "$nandfile" "$outdir"/boot2.raw "$outdir"/boot2.crt "$outdir"/boot2.stmd "$outdir"/boot2.stik "$outdir"/boot2.ebin
echo ">> verify"
runtool tweezer -p "$profile" import-chains "$outdir"/boot2.crt
runtool tweezer -p "$profile" verify -k $tmd_chain -f "$outdir"/boot2.stmd "$outdir"/boot2.tmd
runtool tweezer -p "$profile" verify -k $tik_chain -f "$outdir"/boot2.stik "$outdir"/boot2.tik
echo ">> decrypt"
runtool tong -p "$profile" decrypt -i 0 "$outdir"/boot2.tmd "$outdir"/boot2.tik "$outdir"/boot2.ebin "$outdir"/boot2.bin
echo ">> unpack"
runtool toob2 unpack "$outdir"/boot2.bin "$outdir"/boot2.loader.bin "$outdir"/boot2.payload.bin
