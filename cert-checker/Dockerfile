FROM alpine:latest

RUN apk update && \
    apk add openssl bash coreutils bc mailx && \
    rm -rf /var/cache/apk/*

WORKDIR /app

COPY check_ssl_expiry.sh .
COPY domains.conf .

RUN chmod +x check_ssl_expiry.sh

CMD ["/app/check_ssl_expiry.sh"]

