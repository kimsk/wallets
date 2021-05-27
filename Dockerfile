FROM python:3.9.5

RUN apt-get update && apt-get -y install cmake protobuf-compiler

WORKDIR /wallets
COPY . .

RUN pip install -r requirements.txt && pip install -e .
