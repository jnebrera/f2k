FROM alpine:3.6

# Runtime libraries
RUN apk add --no-cache librdkafka jansson geoip libpcap udns zlib

# envsubst (gettext is very big! install only binary & dependency)
RUN apk add --no-cache --no-cache libintl gettext && \
	cp /usr/bin/envsubst /usr/local/bin/envsubst && \
	apk del gettext

COPY f2k manuf tests/asn.dat tests/asnv6.dat tests/country.dat \
		tests/countryv6.dat docker/release/f2k-start.sh \
		docker/release/f2k.args.env /app/

WORKDIR /app
CMD ["./f2k-start.sh"]
