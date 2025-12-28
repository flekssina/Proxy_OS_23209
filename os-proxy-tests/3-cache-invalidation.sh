#!/usr/bin/env bash

set -e

export INTERACTIVE=true

source common.sh

print_info
init

echo -e "\n${Blu}Downloading samples through proxy:${RCol}"
for i in `seq ${REQUESTS}`; do
	make_request "${i}" "${PROXY_CURL_CMD}"

	if [[ $i == 1 ]]; then
		BEFORE_INV_FIRST_DUR=$duration
	else
		BEFORE_INV_LAST_DUR=$duration
	fi
done

CACHE_SPEED_MULTIPLIER=100
EXPECTED_INV_LAST_DUR=$(echo "scale=3; $BEFORE_INV_FIRST_DUR / $CACHE_SPEED_MULTIPLIER" | bc)

if (( $(echo "$BEFORE_INV_LAST_DUR > $EXPECTED_INV_LAST_DUR" | bc) )); then
	echo -e "\n${BRed}Cache is not working:${RCol}"
	echo -en "The last file was expected to download in less than ${Bold}${EXPECTED_INV_LAST_DUR}s${RCol}, ${Bold}${CACHE_SPEED_MULTIPLIER}${RCol} times "
	echo -e "faster than the first file with ${Bold}${BEFORE_INV_FIRST_DUR}s${RCol}"
	exit 1
else
	echo -e "\n${BGre}Cache is working${RCol}"
fi

SLEEP_S=5
echo -e "\n${Blu}Waiting ${SLEEP_S}s for cache invalidation${RCol}"
sleep ${SLEEP_S}

echo -e "\n${Blu}Downloading samples through proxy:${RCol}"
for i in `seq $(( REQUESTS + 1)) $(( REQUESTS * 2))`; do
	make_request "${i}" "${PROXY_CURL_CMD}"

	if [[ $i == $(( REQUESTS + 1 )) ]]; then
		AFTER_INV_FIRST_DUR=$duration
	else
		AFTER_INV_LAST_DUR=$duration
	fi
done

EXPECTED_INV_FIRST_DUR=$(echo "scale=3; $AFTER_INV_LAST_DUR * $CACHE_SPEED_MULTIPLIER" | bc)

if (( $(echo "$EXPECTED_INV_FIRST_DUR > $AFTER_INV_FIRST_DUR" | bc) )); then
	echo -e "\n${BRed}Cache invalidation is not working:${RCol}"
	echo -en "The first file was expected to download in more than ${Bold}${EXPECTED_INV_FIRST_DUR}s${RCol}, ${Bold}${CACHE_SPEED_MULTIPLIER}${RCol} times "
	echo -e "slower than the last file with ${Bold}${AFTER_INV_LAST_DUR}s${RCol}"
	exit 1
else
	echo -e "\n${BGre}Cache invalidation is working${RCol}"
fi


check_files 1 $(( REQUESTS * 2))
