#!/bin/sh

license="sssteg - A tool for splitting secrets and hiding them in files
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

# UTILITY FUNCTIONS

# wrappers around outputing
die() {
	echo "Error: ${1}" >&2
	exit "${2-1}"
}
warn() {
	echo "Warn: ${1}" >&2
	return 0
}
msg() {
	[ "$quiet" ] || echo "$@"
	return 0
}

# Print prompt ($2) and read variable ($1) from standard input, with echoing disabled
read_secret() {
	# $1: name of variable $2: prompt message
	[ -z "$interactive" ] &&
		die "running in non-interactive mode, cannot ask for $1."
	printf '%s' "$2"
	oldtty="$(stty -g)"
	# shellcheck disable=SC2064
	# $oldtty does not change, so it does not matter when it expands
	trap "stty $oldtty" EXIT
	stty -echo
	read -r "$1"
	stty "$oldtty"
	trap - EXIT
	echo
}

read_prompt() {
	# $1: name of variable $2: prompt message
	[ -z "$interactive" ] &&
		die "running in non-interactive mode, cannot ask for $1."
	printf '%s' "$2"
	read -r "$1"
	echo
}

# Encode a stream of bytes into hexadecimal characters
base16encode() {
	LC_CTYPE=C od -t x1 -v -An - | LC_CTYPE=C tr -d '\n '
}

# Decode a stream of hex characters into raw bytes
base16decode() {
	# script is in a variable, because stdin is taken up by input
	# shellcheck disable=SC2016
	script='
function hex2dec(h      ,i,x,v){
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
}'
	# the C locale doesn't do any fancy multi-byte encoding, so splitting by chars is the same as splitting by bytes
	LC_CTYPE=C awk "$script"
}

# We assume that forked versions correct ssss-combine outputing the secret to stderr
# a return value of 0 means no workarounds are needed, 1: original, old ssss
forked_ssss() {
	version_num="$(LC_ALL=C ssss-combine -v 2>&1 | awk '/Version/{print $2}')"
	major="${version_num%%.*}"
	[ "$major" -gt 0 ] && return 0
	minor="${version_num#*.}"
	[ "$minor" -lt 5 ] && return 1
	# latest upstream, 0.5 has no patch
	[ "$version_num" = "0.5" ] && return 1
	return 0
}

check_dependencies() {
	for dependency; do
		command -v "$dependency" >/dev/null 2>&1 ||
			die "dependency ${dependency} is not installed."
	done
}

# parses an embedded share into $current_label and $current_share
parse_share() {
	echo "$1" | grep -q '-' >/dev/null && current_label="${1%-*-*}"
	current_label="${current_label:-<no label>}"
	current_share="${1##*-}"
}

# Get variables from the various input sources
input_hide() {
	[ "$threshold" ] || threshold="$#"
	threshold="${threshold:-$#}"
	num_files="$#"

	# sanity checks
	# error cases only specific to 1 utility should not be handled by us.
	[ "$secret" ] && [ "$secret_file" ] && die "you can not specify both -s and -f."
	[ "$secret" = "-" ] && [ "$password" = "-" ] && die "you can't pipe both the secret and the password."
	[ "$num_files" -lt 2 ] && die "you must specify at least 2 cover files."
	[ "$num_files" -lt "$threshold" ] && die "threshold can't be higher than the number of cover files."

	if [ "$password" = "-" ]; then
		# password is being piped in
		password="$(cat)"
	elif [ -z "${password+x}" ]; then
		# password was not set
		read_secret password "Choose a password to protect the secrets: "
	fi

	[ -z "$secret" ] && [ -z "$secret_file" ] && read_secret secret "Enter the secret, up to 128 ASCII characters: "

	if [ "$secret_file" ]; then
		secret="$(base16encode <"$secret_file")"
	elif [ "$secret" = "-" ]; then
		secret="$(cat | base16encode)"
	elif [ -z "$secret" ]; then
		read_secret secret "Enter the secret, up to 128 ASCII characters: "
	else
		secret="$(echo "$secret" | base16encode)"
	fi

	return 0
}

inner_hide() {
	[ -d "sssteg" ] || mkdir sssteg

	hex_shares="$(printf '%s' "$secret" | ssss-split -n "$num_files" -t "$threshold" -w "$label" -qx)" || die "there was an error while splitting the secret."
	echo "$hex_shares" | while read -r line; do
		stegofile="${PWD}/sssteg/$(basename "$1")" || die "Cannot read $1"
		if echo "$line" | steghide embed -ef - -cf "$1" -sf "$stegofile" -p "$password" -q; then
			msg "Saved ${stegofile}"
		else
			die "Could not save ${stegofile}"
		fi

		shift
	done
	msg "Done"
	exit 0
}

# Get variables from the various input sources
input_restore() {
	# password is being piped in
	if [ "$password" = "-" ]; then
		password="$(cat)"
	# password was not set
	elif [ -z "${password+x}" ]; then
		read_secret password "Enter password: "
	fi

	[ -z "$output_file" ] || [ "$output_file" = "-" ] && output_file="/dev/stdout"

	if [ -z "${label+x}" ]; then
		for file; do
			item="$(steghide extract -sf "$file" -p "$password" -xf -)" || continue
			parse_share "$item"

			# TODO: less hacky 'array'
			current_label_hex="$(echo "$current_label" | base16encode)"

			echo "$labels" | grep -q "${current_label_hex}\s" >/dev/null || labels="${labels}${current_label_hex} "
		done

		if [ "$(echo "$labels" | LC_CTYPE=C wc -w)" = 1 ]; then
			label_number=1
		elif [ -z "$labels" ]; then
			[ -d "sssteg" ] && warn "did you mean to get the stego files from the sssteg directory?"
			die "no stego files were found. Maybe password is incorrect or wrong files?"
		else
			msg "secrets with these labels were found:"
			i=0
			for hex_label in $labels; do
				i=$((i + 1))
				msg "${i}: $(echo "$hex_label" | base16decode)"
			done
			read_prompt label_number "Type the number of the desired label: "
		fi
		label="$(echo "$labels" | LC_CTYPE=C cut -d ' ' -f "$label_number" | base16decode)"
	fi

	label="${label:-<no label>}"
}

inner_restore() {
	result="$(
		t=0
		for file; do
			item="$(steghide extract -sf "$file" -p "$password" -xf -)" || continue
			parse_share "$item" || continue

			if [ "$current_label" = "$label" ]; then
				t=$((t + 1))
				printf '%s\n' "${t}-${current_share}"
				msg "Read ${file}" >/dev/tty
				[ "$threshold" ] && [ "$t" -ge "$threshold" ] && break
			fi
		done
	)"

	line_count="$(echo "$result" | LC_CTYPE=C wc -l)"
	threshold="${threshold:-$line_count}"
	[ "$line_count" -lt "$threshold" ] && die "fewer stego files were found than threshold. Maybe password is incorrect?"

	# a perfect pipe is split because there is no `pipefail`
	if forked_ssss; then
		restored_hex="$(echo "$result" | ssss-combine -t "$threshold" -qx)" || die "there was an error while combining shares."
		echo "$restored_hex" | tail -n 1 | base16decode >"$output_file" || die "an error occurred while writing secret."
	else
		full_output="$(echo "$result" | ssss-combine -t "$threshold" -qx 2>&1)" || die "there was an error while combining shares."
		echo "$full_output" | while IFS= read -r line || [ -n "$line" ]; do
			if printf "%s\n" "$line" | grep -E '^[0-9a-f]+$'; then
				echo "$line"
			else
				echo "$line" 1>&2
			fi
		done | tail -n 1 | base16decode >"$output_file" || die "an error occurred while writing secret."
	fi

	[ "$output_file" = "/dev/stdout" ] || msg "Saved $output_file"
	msg "Done"
	exit 0
}

# PROGRAM FUNCTIONS

usage() {
	echo "Usage:
  $0 hide    [-q] [-n] [-p <password>] [-s <secret> | -f <secret-file>]
             [-l <label>] [-t <threshold>] <cover-file> <cover-file>...
  $0 restore [-q] [-n] -p <password> [-t <threshold>] [-o <output-file>]
             [-l <label>]  <stego-file> <stego-file>...
  $0 help | -h
  $0 version | -v

Options:
  -p <password>       Password to protect the data in cover files with
                      [default: ask]
  -s <secret>         Hide this string of <=128 bytes [default: ask]
  -f <secret-file>    Hide this file containing <= 128 bytes
  -l <label>          Textual label to help identify the secret
  -t <threshold>      Number of cover files needed to restore the secret
                      [default: all]
  -o <output-file>    File to restore the secret into [default: stdout]
  -q                  Silence all messages to stdout, except the result
  -n                  Non-interactive: fail if user input is needed
  -h                  Print this message
  -v                  Print version
  
For an in-depth description of all options, view man page sssteg(1)." >&2
}

hide() {
	[ -t 1 ] || warn "hide does not support output redirection"

	while [ "$1" ]; do
		case "$1" in
		-q | --quiet) quiet=1 ;;
		-n | --non-interactive) unset interactive ;;

		-p | --password)
			if [ "${2+x}" ]; then
				[ "$password" ] && warn "you can only specify 1 password."
				password="$2"
				shift
			else
				die "'$1' requires an argument."
			fi
			;;
		--password=?*)
			[ "$password" ] && warn "you can only specify 1 password."
			password="${1#*=}"
			;;
		--password=)
			warn "setting no password."
			password=""
			;;

		-l | --label)
			if [ "${2+x}" ]; then
				[ "$label" ] && warn "you can only specify 1 label."
				label="$2"
				shift
			else
				warn "setting an empty label."
			fi
			;;
		--label=?*)
			[ "$label" ] && warn "you can only specify 1 label."
			label="${1#*=}"
			;;
		--label=)
			warn "setting an empty label."
			label=""
			;;

		-s | --secret)
			if [ "$2" ]; then
				[ "$secret" ] && warn "you can only specify 1 secret."
				secret="$2"
				shift
			else
				die "'$1' requires a non-empty argument."
			fi
			;;
		--secret=?*)
			[ "$secret" ] && warn "you can only specify 1 secret."
			secret="${1#*=}"
			;;
		--secret=) die "'$1' requires a non-empty argument." ;;

		-f | --secret-file)
			if [ "$2" ]; then
				[ "$secret_file" ] && warn "you can only specify 1 secret file."
				secret_file="$2"
				shift
			else
				die "'$1' requires a non-empty argument."
			fi
			;;
		--secret-file=?*)
			[ "$secret_file" ] && warn "you can only specify 1 secret file."
			secret_file="${1#*=}"
			;;
		--secret-file=) die "'$1' requires a non-empty argument." ;;

		-t | --threshold)
			if [ "$2" ]; then
				[ "$threshold" ] && warn "you can only specify 1 threshold."
				threshold="$2"
				shift
			else
				die "'$1' requires a non-empty argument."
			fi
			;;
		--threshold=?*)
			[ "$threshold" ] && warn "you can only specify 1 threshold."
			threshold="${1#*=}"
			;;
		--threshold=) die "'$1' requires a non-empty argument." ;;
		--)
			shift
			break
			;;
		-?*) warn "unknown option '$1' (ignored)." ;;
		*) break ;;
		esac
		shift
	done

	input_hide "$@"

	inner_hide "$@"
}

restore() {
	while [ "$1" ]; do
		case $1 in
		-q | --quiet) quiet=1 ;;
		-n | --non-interactive) unset interactive ;;

		-p | --password)
			if [ "${2+x}" ]; then
				[ "$password" ] && warn "you can only specify 1 password."
				password="$2"
				shift
			else
				die "'$1' requires an argument."
			fi
			;;
		--password=?*)
			[ "$password" ] && warn "you can only specify 1 password."
			password="${1#*=}"
			;;
		--password=) password="" ;;

		-l | --label)
			if [ "${2+x}" ]; then
				[ "$label" ] && warn "you can only specify 1 label."
				label="$2"
				shift
			else
				die "'$1' requires an argument."
			fi
			;;
		--label=?*)
			[ "$label" ] && warn "you can only specify 1 label."
			label="${1#*=}"
			;;
		--label=) label="" ;;

		-o | --output-file)
			if [ "$2" ]; then
				[ "$output_file" ] && warn "you can only specify 1 output file."
				output_file="$2"
				shift
			else
				die "'$1' requires a non-empty argument."
			fi
			;;
		--output-file=?*)
			[ "$output_file" ] && warn "you can only specify 1 output file."
			output_file="${1#*=}"
			;;
		--output-file=) die "'$1' requires a non-empty argument." ;;

		-t | --threshold)
			if [ "$2" ]; then
				[ "$threshold" ] && warn "you can only specify 1 threshold."
				threshold="$2"
				shift
			else
				die "'$1' requires a non-empty argument."
			fi
			;;
		--threshold=?*)
			[ "$threshold" ] && warn "you can only specify 1 threshold."
			threshold="${1#*=}"
			;;
		--threshold=) die "'$1' requires a non-empty argument." ;;

		--)
			shift
			break
			;;
		-?*) warn "unknown option '$1' (ignored)." ;;
		*) break ;;
		esac
		shift
	done

	input_restore "$@"

	inner_restore "$@"
}

main() {
	unset quiet
	interactive=1
	unset password
	unset label
	unset secret
	unset secret_file
	unset threshold
	unset output_file
	unset num_files

	unset current_label
	unset current_share

	# Enable quiet mode if output is being redirected.
	[ -t 1 ] || quiet=1

	# Disable interactive functions if output is piped in
	[ -t 0 ] || unset interactive

	check_dependencies ssss-split ssss-combine steghide

	[ -z "$1" ] && die "no subcommand specified. Run $0 -h for usage."

	subcommand="$1"
	shift
	case "$subcommand" in
	hide) hide "$@" ;;
	restore) restore "$@" ;;
	help | -h | --help) usage ;;
	license) echo "$license" >&2 ;;
	version | -V | --version) echo "sssteg 0.1.1" >&2 ;;
	-*) die "subcommand must precede options. Run $0 -h for help." ;;
	*) die "unknown subcommand '$subcommand'. Run $0 -h for help." ;;
	esac

	exit 0
}

if [ -n "$BASH" ]; then
	# TODO: less hacky solution
	# Only run main if not sourced by bash. Bats sources the file for testing.
	# shellcheck disable=SC2039
	[[ ${BASH_SOURCE[0]} == "${0}" ]] && main "$@"
else
	main "$@"
fi

return 0
