#!/bin/sh
# File: scripts/headers.sh

#
# Puts a "File: <path>" header on the first line of every .go, .sql and .sh
# file in the repo (after the shebang for shell scripts), and keeps it correct
# when files move. Assumes file names without spaces.
#
#   scripts/headers.sh          add or fix the headers
#   scripts/headers.sh -check   only report, exit 1 if any header is wrong
set -eu
cd "$(git rev-parse --show-toplevel)"

mode=fix
if [ "${1:-}" = "-check" ]; then
	mode=check
fi

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
bad=0

for f in $(git ls-files --cached --others --exclude-standard -- '*.go' '*.sql' '*.sh'); do
	case "$f" in
	*.go) prefix="// File: " ;;
	*.sql) prefix="-- File: " ;;
	*.sh) prefix="# File: " ;;
	esac

	# Shell scripts keep the shebang on line 1; the header follows it.
	awk -v want="${prefix}${f}" -v prefix="$prefix" '
		NR == 1 && /^#!/ { print; next }
		{ lines[++n] = $0 }
		END {
			i = 1
			if (i <= n && index(lines[i], prefix) == 1) i++
			while (i <= n && lines[i] == "") i++
			print want
			print ""
			for (; i <= n; i++) print lines[i]
		}
	' "$f" >"$tmp"

	if ! cmp -s "$f" "$tmp"; then
		bad=1
		if [ "$mode" = "fix" ]; then
			cat "$tmp" >"$f"
			echo "fixed $f"
		else
			echo "header missing or wrong: $f"
		fi
	fi
done

if [ "$mode" = "check" ] && [ "$bad" -ne 0 ]; then
	exit 1
fi
