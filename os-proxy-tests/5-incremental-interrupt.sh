#!/usr/bin/env bash

set -e

source common.sh

print_info
init

LAST_INTERRUPTED_IDX=0

join_by() {
  local d=${1-} f=${2-}
  if shift 2; then
    printf %s "$f" "${@/#/$d}"
  fi
}

make_interrupted_request() {
	local NUM=$1
	local CMD=$2
	local INTERRUPT_TIME=$NUM

	timeout "${INTERRUPT_TIME}s" bash -c "make_request '${NUM}' '${PROXY_CURL_CMD}'"
	ret=$?

	# If curl was interrupted then ignore that result file
	if [[ $ret == 124 ]]; then
		LAST_INTERRUPTED_IDX=$NUM
		echo
	fi
}

echo -e "\n${Blu}Downloading samples through proxy:${RCol}"
for i in `seq ${REQUESTS}`; do
	make_interrupted_request "${i}" "${PROXY_CURL_CMD}"
done

total_download_time=0
total_download_sum_str=()

for i in `seq ${LAST_INTERRUPTED_IDX}`; do
	((total_download_time = total_download_time + i))
	total_download_sum_str+=("$i")
done

sum_str=$(join_by " + " "${total_download_sum_str[@]}")

if (( $(echo "$total_download_time > $reference_duration" | bc) )); then
	echo -e "\n${BRed}Proxy did not cache partial content:${RCol}"
	echo -en "Reference file was downloaded in ${Bold}${reference_duration}s${RCol}, "
	echo -e "but through proxy it was downloaded only after ${Bold}${total_download_time}s${RCol} ($sum_str)"
	exit 1
fi

check_files $(( LAST_INTERRUPTED_IDX + 1))
