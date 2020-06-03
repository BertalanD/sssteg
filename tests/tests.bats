#!/usr/bin/env bats

src="../sssteg.sh"

export hex_test_strings=('A very very very important secret'
	'Tr0ub4dor&3'
        'correct horse battery staple'
        'S8v9eSZTCuX40fCS62c6HUKolhOOV0xYFejmHLVnx5UNavudokZzsFXWLJ6PhEQKiKCN0G9xuzATqckMdp7TNRCap58cB2YDwYlzyE2djvuihrHhRs3sCykx1tIrZjYB'
        '%`=(?%\|%|:\-.~<**^=>_`>,"?]' # As it turns out, we are fuzzing bats too ;)
	'\n'
	'')
export hex_test_results=('4120766572792076657279207665727920696d706f7274616e7420736563726574'
         '547230756234646f722633'
         '636f727265637420686f727365206261747465727920737461706c65'
         '5338763965535a5443755834306643533632633648554b6f6c684f4f5630785946656a6d484c566e7835554e617675646f6b5a7a734658574c4a36506845514b694b434e30473978757a415471636b4d647037544e524361703538634232594477596c7a794532646a767569687248685273337343796b78317449725a6a5942'
	 '25603d283f255c7c257c3a5c2d2e7e3c2a2a5e3d3e5f603e2c223f5d'
	 '5c6e'
	 '')

source "$src"

export binary_files=( ./bin/* )
export cover_files=( ./images/*.jpg )

export head="Combine shares using Shamir's Secret Sharing Scheme.

ssss-combine -t threshold [-M] [-r -n shares] [-x] [-q] [-Q] [-D] [-v]

"
export forked_versions=( '1.0' '0.5.1' '0.6' '1.2.3' )
export original_versions=( '0.1' '0.2' '0.3' '0.4' '0.5' )

export shares=( 'simple-2-58f078387ff4' '-=*-[;./-1-7c5e1837' 'i have spaces-3-fa95df978fe4' 'WOW capital letters!-2-3025466825e6' 'are you kid*ing-----1-123456789abcdef')
export data=( '58f078387ff4' '7c5e1837' 'fa95df978fe4' '3025466825e6' '123456789abcdef' )
export labels=('simple' '-=*-[;./' 'i have spaces' 'WOW capital letters!' 'are you kid*ing----')

export secret_test_strings=( 'A very very important secret'
	'Tr0ub4dor&3'
	'correct horse battery staple'
	'%`=(?%\|%|:\-.~<**^=>_`>,"?]'
	'\n'
	'Árvíztűrő tükörfúrógép')

# Cleanup if test case was cut short (i.e. failed)
function teardown {
	rmdir sssteg || true
	rm out || true
	rm base16decode || true
}

@test "correctly encode text to base16" {
	source "$src"
	for ((i=0;i<${#hex_test_strings[@]};++i)); do
		output="$(printf '%s' "${hex_test_strings[i]}" | base16encode)"
		[[ "$output" == "${hex_test_results[i]}" ]]
	done
}

@test "correctly decode base16 to text" {
	source "$src"
	for ((i=0;i<${#hex_test_results[@]};++i)); do
                output="$(printf '%s' "${hex_test_results[i]}" | base16decode)"
		echo "$output" > out
                [[ "$output" == "${hex_test_strings[i]}" ]]
        done
}

@test "correct base16 on binary files" {
	for ((i=0;i<${#binary_files[@]};++i)); do
		encoded="$(base16encode <${binary_files[i]})"
		echo -n "$encoded" | base16decode > base16decoded
		cmp -s "${binary_files[i]}" base16decoded
	done
	rm base16decoded
}

@test "detect forked ssss" {
	source "$src"
	for version in "${forked_versions[@]}"; do
		function ssss-combine() {
			printf '%s\n%s' "$head" "Version: ${version}" >&2
		}

		export -f ssss-combine
		forked_ssss
		[ "$?" = 0 ]
	done
}

@test "detect original ssss" {
        source "$src"
        for version in "${original_versions[@]}"; do
                function ssss-combine() {
                        printf '%s\n%s' "$head" "Version: ${version}" >&2
                }

                export -f ssss-combine
                run forked_ssss
                [ "$status" = 1 ]
        done
}

@test "parse shares" {
	source "$src"
	for ((i=0;i<${#shares[@]};++i)); do
		parse_share "${shares[i]}"
		echo "$current_label"
		[ "$current_label" = "${labels[i]}" ]
		[ "$current_share" = "${data[i]}" ]
	done
}

@test "password and secret via command line" {
	for secret in "${secret_test_strings[@]}"; do
			run ../sssteg.sh hide -p "password" -s "$secret" -t 3 ${cover_files[@]}
			[ "$status" = 0 ]

			run ../sssteg.sh restore -p "password" -t 3 -q ./sssteg/*.jpg
			[ "$status" = 0 ]

			[ "${lines[-1]}" = "$secret" ]

			rm -r sssteg
	done
}

@test "password via command line, text secret via pipe" {
	for secret in "${secret_test_strings[@]}"; do
		echo "$secret" | ../sssteg.sh hide -p "password" -s - -t 3 ${cover_files[@]}
		[ "$?" = 0 ]

		run ../sssteg.sh restore -p "password" -t 3 -q ./sssteg/*.jpg
		[ "$status" = 0 ]
		[ "${lines[-1]}" = "$secret" ]
                rm -r sssteg
	done
}

@test "password via command line, binary secret via pipe" {
	for file in "${binary_files[@]}"; do
		cat "$file" | ../sssteg.sh hide -p "password" -s - -t 3 ${cover_files[@]}
		[ "$?" = 0 ]

		run ../sssteg.sh restore -p "password" -t 3 -o out ./sssteg/*.jpg
		[ "$status" = 0 ]
		cmp "$file" out
		rm -r sssteg out
	done
}

@test "password via command line, binary secret via file" {
	for file in "${binary_files[@]}"; do
                ../sssteg.sh hide -p "password" -t 3 -f "$file" ${cover_files[@]}
                [ "$?" = 0 ]

                run ../sssteg.sh restore -p "password" -t 3 -o out ./sssteg/*.jpg
                [ "$status" = 0 ]
                cmp "$file" out
                rm -r sssteg out
        done
}

@test "password via pipe, secret via command line" {
	for password in "${secret_test_strings[@]}"; do
                echo "$password" | ../sssteg.sh hide -p - -s "secret" -t 3 ${cover_files[@]}
                [ "$?" = 0 ]

                run ../sssteg.sh restore -p "$password" -t 3 -q ./sssteg/*.jpg
                [ "$status" = 0 ]
                [ "${lines[-1]}" = "secret" ]
                rm -r sssteg
        done
}

@test "fail with only 1 cover file" {
	run ../sssteg.sh hide -p "password" -s ./bin/bin ${cover_files[1]}
	[ "$status" = 1 ]
	[ "${lines[-1]}" = "Error: you must specify at least 2 cover files." ]
}

@test "fail with too high threshold" {
	run ../sssteg.sh hide -p "password" -s ./bin/bin -t 6 ${cover_files[@]}
	[ "$status" = 1 ]
	[ "${lines[-1]}" = "Error: threshold can't be higher than the number of cover files." ]
}

@test "fail if pipng password and secret" {
	run ../sssteg.sh hide -p - -s -
	[ "$status" = 1 ]
	[ "${lines[-1]}" = "Error: you can't pipe both the secret and the password." ]
}

@test "fail if non-interactive without arguments" {
	run ../sssteg.sh hide ${cover_files[@]} </dev/null
	[ "$status" = 1 ]
	[ "${lines[-1]}" = "Error: running in non-interactive mode, cannot ask for password." ]
}

@test "meaningful error with empty secret via command line" {
	run ../sssteg.sh hide -p "password" -s "" ${cover_files[@]}
	[ "$status" = 1 ]
	[ "${lines[-1]}" = "Error: '-s' requires a non-empty argument." ]
}

@test "meaningful error with empty secret file" {
	run ../sssteg.sh hide -p "password" -f /dev/null ${cover_files[@]}
	[ "$status" = 1 ]
	[ "${lines[-1]}" = "Error: there was an error while splitting the secret." ]
}

@test "meaningful error with empty secret via file" {
	run ../sssteg.sh hide -p "password" -s - ${cover_files[@]} </dev/null
	[ "$status" = 1 ] 
	[ "${lines[-1]}" = "Error: there was an error while splitting the secret." ] 
}

@test "fail with different length shares" {
	../sssteg.sh hide -p "password" -s "short" -t 2 ${cover_files[0]} ${cover_files[1]} ${cover_files[2]}
	../sssteg.sh hide -p "password" -s "this is a super long secret" -t 2 ${cover_files[3]} ${cover_files[4]}

	run ../sssteg.sh restore -p "password" -t 4 ./sssteg/*.jpg
	[ "$status" = 1 ]
	[ "${lines[-1]}" = "Error: there was an error while combining shares." ]
	
	rm -r sssteg
}
