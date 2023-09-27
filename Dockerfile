FROM python:3.10.13-slim-bookworm

RUN apt update && apt upgrade -y

RUN apt install graphviz -y

RUN mkdir /MultilevelSS

COPY requirements.txt /MultilevelSS/

RUN python3 -m pip install --upgrade pip && pip install -r /MultilevelSS/requirements.txt

COPY share.py graph.py entrypoint_share.sh key.json salt.json LICENSE /MultilevelSS/

WORKDIR /MultilevelSS

ENV KEY=hkAEH-UTNaytodwdpx1f8Mo6pLnRe5htnNk29xXps4A=

ENV SALT=darksouls1

ENV IPMONGO=

ENTRYPOINT ["bash","/MultilevelSS/entrypoint_share.sh"]