FROM gcr.io/distroless/cc
COPY origin-linux-x86_64 /bin/origin
ENTRYPOINT ["/bin/origin"]
CMD ["--help"]
