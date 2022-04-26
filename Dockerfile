FROM busybox
COPY attest /bin/attest
CMD ["/bin/attest"]