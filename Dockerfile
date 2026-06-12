FROM golang:1.26-bookworm AS app
WORKDIR /yopass
# Download modules first so the layer is cached across source changes.
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION
RUN VERSION=${VERSION:-$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")} && \
    CGO_ENABLED=0 go build ./cmd/yopass && \
    CGO_ENABLED=0 go build -ldflags "-X main.version=${VERSION}" ./cmd/yopass-server

FROM node:26-bookworm AS website
# node:26 no longer bundles Yarn; enable it via corepack (ships with Node).
RUN corepack enable
COPY website /website
WORKDIR /website
RUN yarn install --frozen-lockfile --network-timeout 600000 && yarn build

FROM gcr.io/distroless/static-debian12
COPY --from=app /yopass/yopass /yopass/yopass-server /
COPY --from=website /website/dist /public
USER 1000
ENTRYPOINT ["/yopass-server"]
