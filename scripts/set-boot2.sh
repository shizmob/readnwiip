#!/bin/sh
set -e

usage() {
	printf "usage: %s [-h] [-p PROFILE] <nandfile> <indir>\n" "$0" >&2
}

profile=retail

while getopts hp: opt; do
	case "$opt" in
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
	sign_args=
	;;
dev|*-dev)
	tmd_chain=Root-CA00000002-CP00000007
	tik_chain=Root-CA00000001-XS00000006
	sign_args=-P
	;;
*)	printf "%s: unknown profile %s\n" "$0" "$profile" >&2; exit 255;;
esac

runtool() {
	tool="$1"; shift
	python3 "$tool".py "$@"
}

nandfile="$1"
indir="$2"

echo ">> encrypt"
runtool tong -p "$profile" update -i 0 "$indir"/boot2.tmd "$indir"/boot2.bin "$indir"/boot2.new.tmd
runtool tong -p "$profile" encrypt -i 0 "$indir"/boot2.new.tmd "$indir"/boot2.tik "$indir"/boot2.bin "$indir"/boot2.new.ebin
echo ">> sign"
runtool tweezer -p "$profile" sign -k $tmd_chain -f $sign_args "$indir"/boot2.new.tmd "$indir"/boot2.new.stmd
runtool tweezer -p "$profile" export "$outdir"/boot2.new.crt $tmd_chain $tik_chain
echo ">> insert"
runtool tsoprocky -p "$profile" insert-boot2 "$nandfile" "$indir"/boot2.new.crt "$indir"/boot2.new.stmd "$indir"/boot2.stik "$indir"/boot2.new.ebin
