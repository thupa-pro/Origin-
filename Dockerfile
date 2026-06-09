FROM rust:1.85-slim-bookworm AS builder

WORKDIR /app
COPY . .

RUN cargo build --release

FROM gcr.io/distroless/cc-debian12
COPY --from=builder /app/target/release/origin /usr/local/bin/origin
USER nobody

ENTRYPOINT ["origin"]
CMD ["--help"]
