FROM python:3.10-alpine

WORKDIR /app

COPY . .

RUN pip3 install -r requirements.txt

EXPOSE 8081

CMD ["python3.10","main.py"]