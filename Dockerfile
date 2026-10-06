FROM python:3.12-alpine
WORKDIR /srv
COPY . .
EXPOSE 8079
CMD ["python", "serve.py"]
