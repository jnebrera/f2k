FROM alpine:3.6

# Runtime libraries
RUN apk add --no-cache librdkafka jansson geoip libpcap udns zlib

# Devel tools
RUN apk add --no-cache --update bash make gcc ca-certificates librdkafka-dev \
	jansson-dev geoip-dev libpcap-dev musl-dev udns-dev zlib-dev \
	libarchive-tools openssl bsd-compat-headers fts-dev cmake \
	&& update-ca-certificates
# bootstrap-tools

WORKDIR /app
