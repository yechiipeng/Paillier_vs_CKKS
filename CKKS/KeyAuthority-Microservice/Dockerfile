FROM python:3.10-slim
WORKDIR /app
COPY src/ /app
COPY requirements.txt /app
RUN pip install --no-cache-dir -r requirements.txt
EXPOSE 5002
CMD ["sh", "-c", "gunicorn --timeout 120 --limit-request-line 8190 --limit-request-field_size 0 -w $((2 * $(nproc) + 1)) --preload -b 0.0.0.0:5002 app:app"]
ENV PYTHONUNBUFFERED=1
