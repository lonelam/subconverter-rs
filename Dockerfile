FROM alpine:edge AS builder

WORKDIR /app
COPY . .

RUN apk add --no-cache cargo==1.86.0-r0 musl-dev perl linux-headers
RUN cargo build --release --bin subconverter --features web-api

FROM alpine:3.21
LABEL maintainer="@jonnyan404"

WORKDIR /app

COPY --from=builder /app/target/release/subconverter /app/
COPY --from=builder /app/base /app/


RUN apk add --no-cache ca-certificates tzdata libgcc libstdc++ \
    && chmod +x /app/subconverter

ENV TZ=Asia/Shanghai

EXPOSE 25500

CMD ["./subconverter"]
