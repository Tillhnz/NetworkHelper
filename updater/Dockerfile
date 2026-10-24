FROM alpine:3.20
RUN apk add --no-cache git python3 docker-cli docker-cli-compose docker-cli-buildx \
    && git config --system --add safe.directory /project
COPY server.py /server.py
EXPOSE 9000
CMD ["python3", "-u", "/server.py"]
