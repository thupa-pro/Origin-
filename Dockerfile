FROM rust:alpine AS builder
RUN apk add --no-cache musl-dev
WORKDIR /app
COPY . .
RUN cargo build --release --bin origin

FROM gcr.io/distroless/cc
COPY --from=builder /app/target/release/origin /bin/origin
ENTRYPOINT ["/bin/origin"]
CMD ["--help"]
