#!/bin/sh
license="$(basename "$0") - hide secrets across multiple files
Copyright (C) 2020 Daniel Bertalan <dani@danielbertalan.dev>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>."

unset password
unset secret
unset secret_file
unset threshold
unset output_file
unset label
unset quiet

die() {
	printf '%s\n' "$1" >&2
	exit 1
}

warn() {
	printf 'Warn: %s\n' "$1" >&2
}

msg() {
	[ -z "$quiet" ] && echo "$@"
}

prompt() {
	[ "$quiet" = 1 ] && printf '%s' "$@" >/dev/tty || printf '%s' "$@"
}
read_secret() {
	oldtty="$(stty -g)"
	stty -echo
	trap 'stty echo' EXIT
	read -r "$@"
	stty "$oldtty"
	trap - EXIT
	echo >/dev/tty
}

# Encode a stream of bytes into hexadecimal
base16encode() {
	cat | od -t x1 -v -An - | tr -d '\n '
}

# Decode hex characters back to raw bytes
base16decode() {
	# script is in a variable, because stdin is taken up by input
	# shellcheck disable=SC2016
	script='
function hex2dec(h	,i,x,v){
  h=tolower(h);sub(/^0x/,"",h)
  for(i=1;i<=length(h);++i){
    x=index("0123456789abcdef",substr(h,i,1))
    if(!x)return"NaN"
    v=(16*v)+x-1
  }
  return v
}

{
  len=split($0,chr,"")
  for(i=1;i<=len;i++){ 
    if(i%2)
      buf=chr[i]  
    else
      printf("%c", hex2dec("0x" buf chr[i]))
    }
}
'
	awk "$script"
}

forked_ssss() {
	version_num="$(ssss-split -v 2>/dev/null | grep Version | awk '{print $2}')"
	major="${version_num%%.*}"
	[ "$major" -gt 0 ] && return 0
	minor="${version_num#*.}"
	[ "$minor" -lt 5 ] && return 1
	# latest upstream, 0.5 has no patch
	[ "$version_num" = "0.5" ] && return 1
	return 0
}

usage() {
	printf '%s\n' "Usage:
  $0 hide [-p <password>] [-l <label>] [-s <secret> | -f <secret-file>]
          [-t <threshold>] <cover-file>...
  $0 restore [-q] [-p <password>] [-l <label>] [-o <output-file>] [-t <threshold>]
          <stego-file>...
  $0 -h

Options:
  -p <password>       Password to protect data in cover files with
                      [default: ask]
  -l <label>          Textual label to help identify the secret
  -s <secret>         Hide this string of <=128 bytes [default: stdin]
  -f <secret-file>    Hide this file containing <= 128 bytes
  -t <threshold>      Number of cover files needed to restore the secret
                      [default: all]
  -o <output-file>    File to restore the secret into [default: stdout]
  -q                  Silence all outputs to stdout, except the result
  -h                  Print this message" >&2
}

hide() {
	while [ "$1" ]; do
		case $1 in
		-p | --password)
			if [ -z "${2+x}" ]; then
				[ "$password" ] && warn "You can only specify 1 password."
				password="$2"
				shift
			else
				die "Error: '$1' requires an argument."
			fi
			;;
		--password=?*)
			[ "$password" ] && warn "You can only specify 1 password."
			password=${1#*=}
			;;
		--password=)
			warn "Setting no password."
			password=""
			;;

		-l | --label)
			if [ "${2+x}" ]; then
				[ "$label" ] && warn "You can only specify 1 label."
				label="$2"
				shift
			else
				warn "Setting an empty label."
			fi
			;;
		--label=?*)
			[ "$label" ] && warn "You can only specify 1 label."
			label=${1#*=}
			;;
		--label=)
			warn "Setting an empty label."
			label=""
			;;

		-s | --secret)
			if [ "$2" ]; then
				[ "$secret" ] && warn "You can only specify 1 secret."
				secret="$2"
				shift
			else
				die "Error: '$1' requires a non-empty argument."
			fi
			;;
		--secret=?*)
			[ "$secret" ] && warn "You can only specify 1 secret."
			secret=${1#*=}
			;;
		--secret=)
			die "Error: '$1' requires a non-empty argument"
			;;

		-f | --secret-file)
			if [ "$2" ]; then
				[ "$secret_file" ] && warn "You can only specify 1 secret file."
				secret_file="$2"
				shift
			else
				die "Error: '$1' requires a non-empty argumnt."
			fi
			;;
		--secret-file=?*)
			[ "$secret_file" ] && warn "You can only specify 1 secret file."
			secret_file=${1#*=}
			;;
		--secret-file=)
			die "Error: '$1' requires a non-empty argument."
			;;

		-t | --threshold)
			if [ "$2" ]; then
				[ "$threshold" ] && warn "You can only specify 1 threshold."
				threshold="$2"
				shift
			else
				die "Error: '$1' requires a non-empty argument."
			fi
			;;
		--threshold=?*)
			[ "$threshold" ] && warn "You can only specify 1 threshold"
			threshold=${1#*=}
			;;
		--threshold=)
			die "Error: '$1' requires a non-empty argument."
			;;

		--)
			shift
			break
			;;
		-?*)
			warn "Unknown option '$1' (ignored)."
			;;
		*)
			break
			;;
		esac
		shift
	done

	[ -t 1 ] || warn "Hide does not support piping output."

	[ "$threshold" = "all" ] && threshold=$#
	threshold="${threshold:-$#}"
	num_files=$#

	# sanity checks
	[ "$secret" ] && [ "$secret_file" ] && die "Error: You can not specify both -s and -f."
	[ "$secret" = "-" ] && [ "$password" = "-" ] && die "Error: You can't pipe both the secret and the password."
	[ "$num_files" -lt "$threshold" ] && die "Error: Threshold can't be higher than the number of cover files."
	# Other error conditions are handled by the utilities.

	if [ "$password" = "-" ]; then
		# password is being piped in
		password="$(cat)"
	elif [ -z "${password+x}" ]; then
		# password was not set
		prompt "Choose a password to protect the secrets: "
		read_secret password
	else
		# password was set empty
		:
	fi

	if [ "$secret" = "-" ]; then
		secret="$(cat)"
	elif [ -z "$secret" ]; then
		prompt "Enter the secret, up to 128 ASCII characters: "
		read_secret secret
	else
		:
	fi

	if [ "$secret_file" ]; then
		secret="$(base16encode <"$secret_file")"
	else
		secret="$(echo "$secret" | base16encode)"
	fi
	
	[ -d "sssteg" ] || mkdir "sssteg"

	printf '%s' "$secret" | ssss-split -n "$num_files" -t "$threshold" -w "$label" -xq | while read -r line || exit 1; do
		stegofile="${PWD}/sssteg/$(basename "$1")" || die "Can't read $1."
		echo "$line" | steghide embed -ef - -cf "$1" -sf "$stegofile" -p "$password" -q && msg "Saved ${stegofile}" || exit 1
		shift
	done

	msg "Done"
	exit 0
}

restore() {
	while [ "$1" ]; do
		case $1 in
		-q | --quiet)
			quiet=1
			;;

		-p | --password)
			if [ "${2+x}" ]; then
				[ "$password" ] && warn "You can only specify 1 password."
				password="$2"
				shift
			else
				die "Error: '$1' requires an argument."
			fi
			;;
		--password=?*)
			[ "$password" ] && warn "You can only specify 1 password."
			password=${1#*=}
			;;
		--password=)
			password=""
			;;

		-l | --label)
			if [ "${2+x}" ]; then
				[ "$label" ] && warn "You can only specify 1 label."
				label="$2"
				shift
			else
				die "Error: '$1' requires an argument."
			fi
			;;
		--label=?*)
			[ "$label" ] && warn "You can only specify 1 label."
			label=${1#*=}
			;;
		--label=)
			label=""
			;;

		-o | --output-file)
			if [ "$2" ]; then
				[ "$output_file" ] && warn "You can only specify 1 output file."
				output_file="$2"
				shift
			else
				die "Error: '$1' requires a non-empty argument."
			fi
			;;
		--output-file=?*)
			[ "$output_file" ] && warn "You can only specify 1 output file."
			output_file=${1#*=}
			;;
		--output-file=)
			die "Error: '$1' requires a non-empty argument."
			;;

		-t | --threshold)
			if [ "$2" ]; then
				[ "$threshold" ] && warn "You can only specify 1 threshold."
				threshold="$2"
				shift
			else
				die "Error: '$1' requires a non-empty argument."
			fi
			;;
		--threshold=?*)
			[ "$threshold" ] && warn "You can only specify 1 threshold"
			threshold=${1#*=}
			;;
		--threshold=)
			die "Error: '$1' requires a non-empty argument."
			;;

		--)
			shift
			break
			;;
		-?*)
			warn "Unknown option '$1' (ignored)."
			;;
		*)
			break
			;;

		esac
		shift
	done

	if [ "$password" = "-" ]; then
		# password is being piped in
		password="$(cat)"
	elif [ -z "${password+x}" ]; then
		# password was not set
		prompt "Enter password: "
		read_secret password
	else
		# password was set empty
		:
	fi

	if [ -z "${label+x}" ]; then
		echo "These labels were found among input files:" >/dev/tty
		i=0
		for file; do
			item="$(steghide extract -sf "$file" -p "$password" -xf - || echo error)"
			[ "$item" = "error" ] && continue
			if echo "$item" | grep '-' >/dev/null; then
				item_label="${item%-*-*}"
				item_label="${item_label:-<no label>}"
			else
				item_label="<no label>"
			fi

			# TODO: less hacky way to do array
			item_label_hex="$(echo "$item_label" | base16encode)"
			if ! echo "$labels" | grep "${item_label_hex}\s" >/dev/null; then
				labels="${labels}${item_label_hex} "
				i=$((i + 1))
				echo "${i}: ${item_label}" >/dev/tty
			fi
		done
		if [ "$i" = 1 ]; then
			msg "Only 1 label found. Continuing"
			number=1
		else
			prompt "Type the number of the desired label: "
			read -r number
		fi
		label="$(echo "$labels" | cut -d " " -f "$number" | base16decode)"
	fi

	[ -z "$output_file" ] || [ "$output_file" = "-" ] && output_file="/dev/stdout"

	# Second pass. Now filtering labels
	result="$(
		t=0
		for file; do
			item="$(steghide extract -sf "$file" -p "$password" -xf - || echo error)"
			[ "$item" = "error" ] && continue
			if echo "$item" | grep '-' >/dev/null; then
				item_label="${item%-*-*}"
				item_label="${item_label:-<no label>}"
			else
				item_label="<no label>"
			fi

			if [ "$item_label" = "${label:=<no label>}" ]; then
				[ "$threshold" ] && [ "$t" -ge "$threshold" ] && break
				t=$((t + 1))
				# This will only be printed to the variable through command substitution
				printf '%s\n' "$t-${item##*-}"
			fi
		done
	)"
	lines="$(echo "$result" | wc -l)"
	[ "$lines" -lt "$threshold" ] > /dev/null 2>&1 && die "Fewer stego files were found than the threshold. Maybe wrong password?"

	# The original ssss writes results to stderr. Grepping for hex characters to filter out warnings and other irrelevant cr*p.
	forked_ssss || echo "$result" | ssss-combine -t "${threshold:-$lines}" -qx 2>&1 | grep -E '^[0-9a-fA-F]+$' | tail -n 1 | base16decode >"$output_file"

	forked_ssss && echo "$result" | ssss-combine -t "${threshold:-$lines}" -qx | base16decode >"$output_file"

	exit 0
}

# Do not print messages to stdout if it is being redirected
[ -t 1 ] || quiet=1

# Print usage if no subcommand or argument is given
[ -z "$1" ] && die "Error: no subcommand specified. Run $0 -h for usage."

subcommand=$1
shift
case "$subcommand" in
hide)
	hide "$@"
	;;
restore)
	restore "$@"
	;;
-h | --help | help)
	usage
	exit 0
	;;
license)
	echo "$license"
	exit 0
	;;
-*)
	die "Error: subcommand must precede options. Run $0 -h for help."
	;;
*)
	die "Error: unknown subcommand '$subcommand'. Run $0 -h for help."
	;;
esac
