FROM docker.io/library/golang:1.22 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /policy-engine ./cmd/policy-engine

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /policy-engine /policy-engine
EXPOSE 8900
ENTRYPOINT ["/policy-engine"]
