FROM python:latest

COPY test/requirements.txt /requirements.txt
COPY scan/requirements.txt /scan-requirements.txt
RUN pip install -r /requirements.txt -r /scan-requirements.txt

COPY common/wait-for-it.sh /wait-for-it.sh

RUN mkdir /test
COPY test/*.py /test
COPY scan/libmailgoose /test/libmailgoose

WORKDIR /test/

CMD python -m unittest discover
