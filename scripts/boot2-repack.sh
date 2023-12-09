#!/bin/sh
set -e

usage() {
	printf "usage: %s [-h] [-b] [-p PROFILE] [-s TMD_SIGNER] <nandfile> <indir>\n" "$0" >&2
}

profile=retail
tmd_chain=
backup=

while getopts hbp:s: opt; do
	case "$opt" in
	h) usage; exit 0;;
	b) backup=1;;
	p) profile="$OPTARG";;
	s) tmd_chain="$OPTARG";;
	?) usage; exit 255;;
	esac
done
shift $(($OPTIND - 1))
[ $# -eq 2 ] || { usage; exit 255; }
nandfile="$1"
outdir="$2"

case "$profile" in
retail|*-retail)
	sign_args=
	;;
dev|*-dev)
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
[ -n "$tmd_chain" ] || tmd_chain=$(runtool tweezer -p "$profile" issuer "$indir"/boot2.stmd)

echo ">> pack"
runtool toob2 pack "$indir"/boot2.loader.bin "$indir"/boot2.payload.bin "$indir"/boot2.new.bin
echo ">> encrypt"
runtool tong -p "$profile" update -i 0 "$indir"/boot2.tmd "$indir"/boot2.new.bin "$indir"/boot2.new.tmd
runtool tong -p "$profile" encrypt -i 0 "$indir"/boot2.new.tmd "$indir"/boot2.tik "$indir"/boot2.new.bin "$indir"/boot2.new.ebin
echo ">> sign"
runtool tweezer -p "$profile" sign -k $tmd_chain -f $sign_args -t 70 -t 71 -t 72 -t 73 "$indir"/boot2.new.tmd "$indir"/boot2.new.stmd
runtool tweezer -p "$profile" export-chains "$outdir"/boot2.new.crt $tmd_chain $(runtool tweezer -p "$profile" issuer "$indir"/boot2.stik)
echo ">> insert"
runtool tsoprocky -p "$profile" insert-boot2 ${backup:+-b} "$nandfile" "$indir"/boot2.new.crt "$indir"/boot2.new.stmd "$indir"/boot2.stik "$indir"/boot2.new.ebin
