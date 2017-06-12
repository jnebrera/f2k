FROM alpine:3.6

# Runtime libraries
RUN apk add --no-cache librdkafka jansson geoip libpcap udns zlib

# Devel tools
# ncurses - expat: deps for xml-coreutils
RUN apk add --no-cache bash build-base ca-certificates librdkafka-dev \
		jansson-dev geoip-dev libpcap-dev udns-dev zlib-dev \
		libarchive-tools openssl bsd-compat-headers fts-dev cmake cgdb \
		valgrind ncurses-dev slang-dev expat-dev && \
	apk add --no-cache \
		--repository http://dl-3.alpinelinux.org/alpine/edge/testing/ lcov && \
	update-ca-certificates
# bootstrap-tools

WORKDIR /app
