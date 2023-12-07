FROM python:latest

COPY test/requirements.txt /requirements.txt
RUN pip install -r /requirements.txt

COPY common/wait-for-it.sh /wait-for-it.sh

RUN mkdir /test
COPY test/*.py /test

WORKDIR /test/

CMD python -m unittest discover
