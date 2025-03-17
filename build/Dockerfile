FROM cgr.dev/chainguard/go AS builder
WORKDIR /tmp/builder

ARG RELEASE
ARG COMMIT
ARG BUILD_DATE
ARG PROJECT=github.com/alacuku/falco-operator

RUN test -n "$RELEASE" || ( echo "The RELEASE argument is unset. Aborting" && false )
RUN test -n "$COMMIT" || ( echo "The COMMIT argument is unset. Aborting" && false )
RUN test -n "$BUILD_DATE" || ( echo "The BUILD_DATE argument is unset. Aborting" && false )

COPY go.mod ./go.mod
COPY go.sum ./go.sum
RUN  go mod download

COPY . ./

RUN CGO_ENABLED=0 \
    GOOS=$(go env GOOS) \
    GOARCH=$(go env GOARCH) \
    go build -ldflags \
    "-s \
    -w \
    -X '${PROJECT}/cmd/sidecar/main.semVersion=${RELEASE}' \
    -X '${PROJECT}/cmd/sidecar/main.gitCommit=${COMMIT}' \
    -X '${PROJECT}/cmd/sidecar/main.buildDate=${BUILD_DATE}'" \
    ./cmd/sidecar/main.go

RUN echo ${RELEASE}

FROM cgr.dev/chainguard/static:latest

COPY --from=builder /tmp/builder/sidecar /usr/bin/sidecar

ENTRYPOINT [ "/usr/bin/sidecar" ]