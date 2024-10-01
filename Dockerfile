FROM golang:1.23 AS build
WORKDIR /build
COPY . .
RUN go mod download 
RUN CGO_ENABLED=0 GOOS=linux go build -o amp-encryption-server

FROM scratch
COPY --from=build /build/amp-encryption-server /
EXPOSE 8080
CMD ["/amp-encryption-server"]