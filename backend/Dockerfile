# Build context is the repo root so the manifest module is available:
#   docker build -f backend/Dockerfile .
FROM golang:1.27 AS build
WORKDIR /src
COPY manifest/go.mod manifest/go.sum ./manifest/
COPY backend/go.mod backend/go.sum ./backend/
WORKDIR /src/backend
RUN go mod download
WORKDIR /src
COPY manifest ./manifest
COPY backend ./backend
WORKDIR /src/backend
RUN CGO_ENABLED=0 go build -o /out/backend ./cmd
RUN mkdir /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/backend /backend
COPY --from=build --chown=nonroot:nonroot /out/data /data
ENV PORT=8080 DATA_DIR=/data
VOLUME /data
EXPOSE 8080
ENTRYPOINT ["/backend"]
