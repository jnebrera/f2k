#!/usr/bin/env sh

readonly OUT_FILE=f2k.args

# Assign default value if not value
function zz_var {
	eval "local readonly currval=\"\$$1\""
	if [ -z "${currval}" ]; then
		value="$(printf "%s" "$2" | sed 's%"%\\"%g')"
		eval "export $1=\"$value\""
	fi
}

#
# ZZ variables
#

zz_var F2K_NTHREADS 3
zz_var KAFKA_BROKERS kafka
zz_var KAFKA_TOPIC flow
zz_var COLLECTOR_PORT 2055


if [ "x$ENABLE_DNS" == "xy" ]; then
	DNS_PTR_ARG="--enable-ptr-dns="

	zz_var DNS_CACHE_SIZE_MB 20480
	DNS_CACHE_SIZE_MB_ARG="--dns-cache-size-mb=${DNS_CACHE_SIZE_MB}"
	zz_var DNS_CACHE_TIMEOUT 14400
	DNS_CACHE_TIMEOUT_ARG="--dns-cache-timeout-s=${DNS_CACHE_TIMEOUT}"

	export F2K_DNS_ARGS=$(printf "%s\n%s\n%s\n" "$DNS_PTR_ARG" "$DNS_CACHE_SIZE_MB_ARG" "$DNS_CACHE_TIMEOUT_ARG")
fi

envsubst < ${OUT_FILE}.env > ${OUT_FILE}

#
# All RDKAFKA_ vars will be passed to librdkafka as-is
#

# Override librdkafka defaults
zz_var RDKAFKA_SOCKET_KEEPALIVE_ENABLE true
zz_var RDKAFKA_MESSAGE_SEND_MAX_RETRIES 0

# Read all librdkafka envs, chop first RDKAFKA, and change '_' for '.'
env | sed -n '/^RDKAFKA_/s/RDKAFKA_//p;' | tr 'A-Z_' 'a-z.' | \
while IFS='=' read rdkafka_key rdkafka_val; do
	printf "%s\n-X=%s=%s" "$F2K_RDKAFKA_ARGS" "$rdkafka_key" "$rdkafka_val" \
		>> ${OUT_FILE}
done

#
# Defined netflow probes
#
zz_var NETFLOW_PROBES '{"sensors_networks":{}}'
printf "%s" $NETFLOW_PROBES > probes.json
exec ./f2k ${OUT_FILE}
