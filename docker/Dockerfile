FROM alpine:3.7 as f2k-dev

WORKDIR /app

# Devel tools
# ncurses, slang, expat: deps for xml-coreutils
RUN apk add --no-cache \
	bash \
	bsd-compat-headers \
	build-base \
	ca-certificates \
	cgdb \
	cmake \
	expat-dev \
	fts-dev \
	geoip-dev \
	jansson-dev \
	libarchive-tools \
	libpcap-dev \
	librdkafka-dev \
	ncurses-dev \
	openssl \
	slang-dev \
	udns-dev \
	zlib-dev \
	&& apk add --no-cache \
		--repository http://dl-cdn.alpinelinux.org/alpine/edge/testing/ \
		lcov \
		valgrind \
	&& update-ca-certificates
ENTRYPOINT ["/bin/bash", "-c"]
CMD ["/bin/bash"]


FROM alpine:3.7

WORKDIR /app

# envsubst (gettext is very big! install only binary & dependency)
RUN apk add --no-cache --no-cache libintl gettext && \
	cp /usr/bin/envsubst /usr/local/bin/envsubst && \
	apk del gettext

# Runtime libraries
RUN apk add --no-cache librdkafka jansson geoip libpcap udns zlib

COPY \
	docker/release/f2k-start.sh \
	docker/release/f2k.args.env \
	f2k \
	manuf \
	tests/asn.dat \
	tests/asnv6.dat \
	tests/country.dat \
	tests/countryv6.dat \
	/app/
ENTRYPOINT /app/f2k-start.sh
