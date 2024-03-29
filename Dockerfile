FROM rust:latest as builder

# based on https://blog.logrocket.com/packaging-a-rust-web-service-using-docker/

RUN mkdir /build/
ADD . /build/
WORKDIR /build/saml_test_server/
RUN cargo build --release

FROM debian:buster-slim
ARG APP=/usr/src/app

RUN apt-get update \
    && apt-get -y upgrade \
    && apt-get install -y ca-certificates tzdata dumb-init \
    && rm -rf /var/lib/apt/lists/*

ENV TZ=Etc/UTC \
    APP_USER=appuser

RUN groupadd $APP_USER \
    && useradd -g $APP_USER $APP_USER \
    && mkdir -p ${APP}

COPY --from=builder /build/target/release/saml_test_server ${APP}/saml_test_server

RUN chown -R $APP_USER:$APP_USER ${APP}

USER $APP_USER
WORKDIR ${APP}

# dumb-init fixes the "can't ctrl-c to kill this" problem
# <https://github.com/Yelp/dumb-init>
ENTRYPOINT ["/usr/bin/dumb-init", "--"]

CMD ["./saml_test_server"]
