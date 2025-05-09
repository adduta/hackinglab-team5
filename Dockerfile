FROM golang as build-env
WORKDIR /go/src/sshhipot
COPY ./sshhipot /go/src/sshhipot

RUN go mod init github.com/magisterquis/sshhipot
RUN go mod tidy 
RUN go build -o /go/bin/sshhipot
FROM gcr.io/distroless/base
COPY --from=build-env /go/bin/sshhipot /
COPY --from=build-env /go/src/sshhipot/passwords /passwords
EXPOSE 2022
VOLUME /data
CMD ["/sshhipot", "-cs", "127.0.0.1:22", "-cu", "test", "-p", "123456", "-ck", "id_rsa.XXX", "-l", "0.0.0.0:2022", "-pf", "/passwords"]