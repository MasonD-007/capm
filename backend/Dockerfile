FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/backend ./cmd

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/backend /backend
ENV PORT=8080
EXPOSE 8080
ENTRYPOINT ["/backend"]
