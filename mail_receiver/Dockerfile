FROM python:3.12-alpine3.18

RUN apk add tzdata git

ENV TZ=Europe/Warsaw
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

COPY scan /scan
COPY mail_receiver/requirements.txt /requirements.txt
RUN pip install -r /requirements.txt

COPY common /opt/common/
COPY mail_receiver/server.py /opt/server.py
