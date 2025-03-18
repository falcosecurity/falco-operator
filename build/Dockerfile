FROM cgr.dev/chainguard/go AS builder
WORKDIR /tmp/builder

ARG RELEASE
ARG COMMIT
ARG BUILD_DATE
ARG PROJECT=github.com/alacuku/falco-operator
ARG OPERATOR

RUN test -n "$RELEASE" || ( echo "The RELEASE argument is unset. Aborting" && false )
RUN test -n "$COMMIT" || ( echo "The COMMIT argument is unset. Aborting" && false )
RUN test -n "$BUILD_DATE" || ( echo "The BUILD_DATE argument is unset. Aborting" && false )
RUN test -n "$OPERATOR" || ( echo "The OPERATOR argument is unset. Aborting" && false )

COPY go.mod ./go.mod
COPY go.sum ./go.sum
RUN  go mod download

# Copy the go source
COPY cmd/${OPERATOR}/main.go cmd/${OPERATOR}/main.go
COPY api/ api/
COPY internal/ internal/

RUN CGO_ENABLED=0 \
    GOOS=$(go env GOOS) \
    GOARCH=$(go env GOARCH) \
    go build -ldflags \
    "-s \
    -w \
    -X '${PROJECT}/internal/pkg/version.SemVersion=${RELEASE}' \
    -X '${PROJECT}/internal/pkg/version.GitCommit=${COMMIT}' \
    -X '${PROJECT}/internal/pkg/version.BuildDate=${BUILD_DATE}'" \
    -o ${OPERATOR} ./cmd/${OPERATOR}/main.go

RUN echo ${RELEASE}

FROM cgr.dev/chainguard/static:latest

ARG OPERATOR

COPY --from=builder /tmp/builder/${OPERATOR} /usr/bin/manager
USER 65532:65532

ENTRYPOINT [ "/usr/bin/manager" ]
