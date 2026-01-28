
FROM cgr.dev/chainguard/static:latest

ARG TARGETARCH

COPY bin/linux/${TARGETARCH}/manager /usr/bin/manager

USER 65532:65532

ENTRYPOINT [ "/usr/bin/manager" ]
