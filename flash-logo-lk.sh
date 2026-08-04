#!/usr/bin/env bash
#
# flash-logo-lk.sh - flash a patched boot logo and/or LK bootloader to an
# unlocked MediaTek device over fastboot.
#
# Point it at a directory (default: the current one) that contains:
#
#   logo.bin.orig                  stock dump  (its size = the LK/logo backup)
#   logo.bin.new                   built by build-logo.py (aliases:
#                                  logo.bin.patched, logo.bin.lineage)
#   lk_<slot>.bin.orig             stock dump, one per LK partition
#   lk_<slot>.bin.patched          built by patch_lk_orangestate.py
#
# Sizes are NOT hardcoded: an LK image must match its own stock dump byte for
# byte in length, and the logo must fit the partition size reported by the
# bootloader itself. Nothing is assumed about the chipset.
#
# Risk: the logo partition is cosmetic and not required to boot. lk IS the
# bootloader -- a bad write there can hard-brick past fastboot, and recovery
# then needs mtkclient over BROM plus the stock dumps.
#
set -euo pipefail

DEVDIR="${DEVDIR:-$(pwd)}"
DRY_RUN=0
ASSUME_YES=0
LOGO_ONLY=0
LK_ONLY=0
RESTORE=0

usage() {
	cat <<'EOF'
Usage: ./flash-logo-lk.sh [options] [device-dir]

  -n, --dry-run    print every fastboot command instead of running it
  -y, --yes        do not prompt before writing
      --logo-only  flash only the logo partition (bootloader untouched)
      --lk-only    flash only the LK partitions
      --restore    write the STOCK logo + lk images back
  -h, --help       this text

device-dir defaults to the current directory.
EOF
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	-n | --dry-run) DRY_RUN=1 ;;
	-y | --yes) ASSUME_YES=1 ;;
	--logo-only) LOGO_ONLY=1 ;;
	--lk-only) LK_ONLY=1 ;;
	--restore) RESTORE=1 ;;
	-h | --help)
		usage
		exit 0
		;;
	-*)
		echo "unknown option: $1" >&2
		usage >&2
		exit 2
		;;
	*) DEVDIR="$1" ;;
	esac
	shift
done

log() { printf '\n\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*" >&2; }
die() {
	printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2
	exit 1
}
run() {
	if ((DRY_RUN)); then
		printf '    \033[2m[dry-run]\033[0m %s\n' "$*"
	else
		printf '    \033[2m$\033[0m %s\n' "$*"
		"$@"
	fi
}
getvar() { fastboot getvar "$1" 2>&1 | sed -n "1s/^$1: //p" | tr -d '\r'; }
gate() { if ((DRY_RUN)); then warn "$*"; else die "$*"; fi; }

DEVDIR="$(cd "$DEVDIR" && pwd)" || die "no such directory"
((LOGO_ONLY && LK_ONLY)) && die "--logo-only and --lk-only are mutually exclusive"

log "Preflight  ($DEVDIR)"
command -v fastboot >/dev/null || die "fastboot not on PATH"

# Build the part list from what is actually on disk.
declare -a PARTS=()

if ((LK_ONLY == 0)); then
	if ((RESTORE)); then
		src="$DEVDIR/logo.bin.orig"
		[[ -f "$src" ]] || die "missing $src"
	else
		# Accept the build-logo.py default name, plus a couple of common aliases.
		src=""
		for cand in logo.bin.new logo.bin.patched logo.bin.lineage; do
			[[ -f "$DEVDIR/$cand" ]] && { src="$DEVDIR/$cand"; break; }
		done
		[[ -n "$src" ]] || die "no built logo found in $DEVDIR (expected logo.bin.new)"
	fi
	PARTS+=("logo:$src")
fi

if ((LOGO_ONLY == 0)); then
	shopt -s nullglob
	for stock in "$DEVDIR"/lk*.bin.orig; do
		part="$(basename "$stock")"
		part="${part%.bin.orig}"
		src="$DEVDIR/$part.bin.patched"
		((RESTORE)) && src="$stock"

		# Some devices never provision the inactive slot: its LK partition reads
		# back as all zeros. There is nothing to patch and writing anything there
		# would be a change away from stock, so skip it.
		nonzero=$(LC_ALL=C tr -d '\0' <"$stock" | wc -c)
		if [[ ! -s "$stock" ]] || ((nonzero == 0)); then
			warn "$part is entirely zero on this device (slot never provisioned) -- skipping it"
			continue
		fi

		[[ -f "$src" ]] || die "missing $src"
		# A truncated bootloader is the classic way to brick these: the image
		# must be exactly as long as the stock dump of the same partition.
		a=$(stat -c %s "$stock")
		b=$(stat -c %s "$src")
		((a == b)) || die "$(basename "$src") is $b bytes but $part is $a bytes"
		PARTS+=("$part:$src")
	done
	shopt -u nullglob
	((${#PARTS[@]})) || die "no lk*.bin.orig found in $DEVDIR"
fi

for e in "${PARTS[@]}"; do
	printf '  %-6s <- %-24s (%s bytes)\n' "${e%%:*}" "$(basename "${e#*:}")" "$(stat -c %s "${e#*:}")"
done

if [[ -z "$(fastboot devices)" ]]; then
	gate "no fastboot device detected -- reboot into the bootloader first (adb reboot bootloader)"
else
	# fastbootd (Android 10+) always answers is-userspace=yes. Older bootloaders
	# do not implement the variable at all and return empty -- that is a legacy
	# bootloader, which is exactly what we want, so only "yes" is a problem.
	userspace="$(getvar is-userspace)"
	if [[ "$userspace" == "yes" ]]; then
		gate "device is in fastbootd; these are physical partitions and need the bootloader's fastboot (fastboot reboot bootloader)"
	elif [[ -z "$userspace" ]]; then
		warn "bootloader does not implement is-userspace (legacy MTK) -- assuming bootloader fastboot"
	fi
	u="$(getvar unlocked)"
	[[ "$u" == "yes" ]] || warn "getvar unlocked reported '$u' -- flashing may be rejected"
	printf '  product: %s   slot: %s   unlocked: %s\n' "$(getvar product)" "$(getvar current-slot)" "$u"

	for e in "${PARTS[@]}"; do
		part="${e%%:*}" file="${e#*:}"
		psize_hex="$(getvar "partition-size:$part")"
		[[ -n "$psize_hex" ]] || { gate "bootloader does not expose partition '$part'"; continue; }
		# fastboot reports this as hex, sometimes with a 0x prefix and sometimes
		# bare ("b00000"), so normalise before doing arithmetic on it.
		psize_hex="${psize_hex#0x}"
		[[ "$psize_hex" =~ ^[0-9a-fA-F]+$ ]] || die "unparseable partition-size:$part = '$psize_hex'"
		psize=$((16#$psize_hex))
		fsize=$(stat -c %s "$file")
		((fsize <= psize)) || die "$(basename "$file") ($fsize) exceeds $part ($psize)"
		# LK must fill its partition exactly; logo is allowed to be smaller.
		if [[ "$part" == lk* ]] && ((fsize != psize)); then
			die "$(basename "$file") is $fsize but the device reports $part = $psize"
		fi
		printf '  partition-size:%-6s = %s (%s bytes) -- image fits\n' "$part" "$psize_hex" "$psize"
	done
fi

if ((DRY_RUN == 0 && ASSUME_YES == 0)); then
	echo
	if ((RESTORE)); then
		echo "  This restores the STOCK images listed above."
	elif ((LOGO_ONLY)); then
		echo "  This overwrites the logo partition only. The bootloader is untouched."
	else
		echo "  This overwrites the BOOTLOADER. If it goes wrong the device may not"
		echo "  reach fastboot again and will need mtkclient over BROM to recover."
	fi
	read -r -p "  Type 'flash' to continue: " reply
	[[ "$reply" == "flash" ]] || die "aborted by user"
fi

log "Flashing"
for e in "${PARTS[@]}"; do run fastboot flash "${e%%:*}" "${e#*:}"; done

log "Rebooting"
run fastboot reboot

cat <<'EOF'

  Done. On the next boot expect: the new splash, no "Orange State" text, and
  no ~5s pause before the boot animation.

  If something looks wrong but the device still boots: ./flash-logo-lk.sh --restore

EOF
