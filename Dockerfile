FROM golang:1.23-alpine AS build
WORKDIR /build
RUN apk update && apk upgrade && apk add --no-cache ca-certificates
RUN update-ca-certificates
COPY . .
RUN go mod download 
RUN CGO_ENABLED=0 GOOS=linux go build -o amp-encryption-server

FROM scratch
COPY --from=build /build/amp-encryption-server /
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
EXPOSE 8080
CMD ["/amp-encryption-server"]