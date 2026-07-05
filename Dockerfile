# MirageOT - ICS/OT deception platform (zero dependencies)
# Build:  docker build -t mirageot .
# Run:
#   docker run -d --name mirageot \
#       -p 502:502 -p 102:102 -p 20000:20000 -p 2404:2404 -p 44818:44818 \
#       -p 8080:8080 -p 21:21 -p 23:23 -p 8888:8888 \
#       -v $PWD/config.json:/app/config.json \
#       -v $PWD/logs:/var/log/mirageot \
#       mirageot --config /app/config.json
#
# The console is on 8888. Reach it from your SOC network only.
#
# SECURITY: run on an ISOLATED, MONITORED segment. Egress must be drop-all except your
# log/syslog collector. A honeypot must never be able to pivot into real OT assets.
FROM python:3.12-slim
WORKDIR /app
COPY mirageot.py ics_honeypot.py gen_tokens.py ./
RUN mkdir -p /var/log/mirageot
EXPOSE 502 102 20000 2404 44818 8080 21 23 8888
ENTRYPOINT ["python", "mirageot.py"]
CMD ["--profile", "siemens_s7_1200"]
