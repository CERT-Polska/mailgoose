FROM python:3.11.2-alpine

RUN apk add bash openssl git tzdata opendkim opendkim-utils

ENV TZ=Europe/Warsaw
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

WORKDIR /app/
COPY app/requirements.txt /requirements.txt
COPY app/translations/requirements.txt /translations/requirements.txt

RUN pip install -r /requirements.txt

COPY common/wait-for-it.sh /wait-for-it.sh
COPY common/mail_receiver_utils.py /app/mail_receiver_utils.py

COPY app/ /app/
RUN openssl rand -hex 10 > /app/build_id
