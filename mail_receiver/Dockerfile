FROM python:3.12-alpine3.18

RUN apk add tzdata

ENV TZ=Europe/Warsaw
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

COPY mail_receiver/requirements.txt /requirements.txt
RUN pip install -r /requirements.txt

COPY common/mail_receiver_utils.py /opt/mail_receiver_utils.py
COPY mail_receiver/server.py /opt/server.py
