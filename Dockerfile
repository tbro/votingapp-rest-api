FROM ekidd/rust-musl-builder AS builder

COPY --chown=rust:rust ./Cargo.lock ./Cargo.lock
COPY --chown=rust:rust ./Cargo.toml ./Cargo.toml
COPY --chown=rust:rust ./src ./src

RUN cargo build --release

FROM scratch

ENV SAWTOOTH_REST_URI=${SAWTOOTH_REST_URI:-http://localhost:8008}
COPY --from=builder ["/home/rust/src/target/x86_64-unknown-linux-musl/release/rest-api", "/rest-api"]
ENV RUST_LOG=info

CMD ["/rest-api"]
