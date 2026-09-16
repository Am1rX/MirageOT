FROM python:3.12-slim
WORKDIR /app
COPY mirageot.py ./
COPY mirageot/ ./mirageot/
COPY config.example.json ./
RUN mkdir -p /var/log/mirageot && chown -R 10001:10001 /var/log/mirageot /app
USER 10001:10001
EXPOSE 502 102 20000 2404 44818 8080 21 23 8888
ENTRYPOINT ["python", "mirageot.py"]
CMD ["--config", "/app/config.example.json"]
