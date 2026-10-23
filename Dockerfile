FROM rust:bookworm AS build
WORKDIR /build
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY src ./src
COPY assets ./assets
RUN cargo build --release --locked -j 4

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 selfcheck \
    && useradd --uid 10001 --gid 10001 --create-home selfcheck \
    && mkdir /state && chown 10001:10001 /state
COPY --from=build /build/target/release/php-selfcheck /usr/local/bin/php-selfcheck
USER 10001:10001
WORKDIR /state
EXPOSE 8080
ENTRYPOINT ["php-selfcheck"]
CMD ["serve", "--config", "/state/config.json", "--bind", "0.0.0.0"]
