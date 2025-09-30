FROM python:3.11-slim

WORKDIR /app

COPY . /app

RUN chmod +x /app/main.py

EXPOSE 5000

ENV PYTHONUNBUFFERED=1

CMD ["python", "main.py"]
