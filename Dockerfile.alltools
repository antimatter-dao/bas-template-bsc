# Support setting various labels on the final image
ARG COMMIT=""
ARG VERSION=""
ARG BUILDNUM=""

# Build Geth in a stock Go builder container
FROM golang:1.17-alpine3.16 as builder

RUN apk add --no-cache make gcc musl-dev linux-headers git bash

ADD . /go-ethereum
RUN cd /go-ethereum && make all-static

# Pull all binaries into a second stage deploy alpine container
FROM alpine:3.16

ARG BSC_USER=bsc
ARG BSC_USER_UID=1000
ARG BSC_USER_GID=1000

ENV BSC_HOME=/bsc
ENV HOME=${BSC_HOME}
ENV DATA_DIR=/data

ENV PACKAGES ca-certificates jq \
  bash bind-tools tini \
  grep curl sed

RUN apk add --no-cache $PACKAGES \
  && rm -rf /var/cache/apk/* \
  && addgroup -g ${BSC_USER_GID} ${BSC_USER} \
  && adduser -u ${BSC_USER_UID} -G ${BSC_USER} --shell /bin/bash --no-create-home -D ${BSC_USER} \
  && addgroup ${BSC_USER} tty

WORKDIR ${BSC_HOME}

COPY --from=builder /go-ethereum/build/bin/* /usr/local/bin/

RUN mkdir -p ${DATA_DIR} \
    && chown -R ${BSC_USER_UID}:${BSC_USER_GID} ${BSC_HOME} ${DATA_DIR}

VOLUME ${DATA_DIR}

USER ${BSC_USER_UID}:${BSC_USER_GID}

# rpc ws graphql
EXPOSE 8545 8546 8547 30303 30303/udp

# Add some metadata labels to help programatic image consumption
ARG COMMIT=""
ARG VERSION=""
ARG BUILDNUM=""

LABEL commit="$COMMIT" version="$VERSION" buildnum="$BUILDNUM"

ENTRYPOINT ["/sbin/tini", "--"]