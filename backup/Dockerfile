# alpine 3.24 (multi-arch index digest)
FROM alpine@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf

RUN apk add --no-cache restic sqlite

COPY --chmod=0755 backup.sh /backup.sh

USER 65532:65532
ENTRYPOINT ["/backup.sh"]
