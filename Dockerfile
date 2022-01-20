FROM python:3.9.10-alpine3.15

RUN apk update
RUN apk add git
RUN python -m pip install --upgrade pip
RUN pip install --upgrade pip setuptools 
RUN pip install medallion

# Set up the default configuration files
RUN mkdir -p /opt/taxii/data
RUN mkdir -p /opt/taxii/conf.d
COPY medallion.conf /opt/taxii/conf.d/medallion.conf
ARG MEDALLION_CONFFILE=/opt/taxii/confi.d/medallion.conf
ENV MEDALLION_CONFFILE "${MEDALLION_CONFFILE}"
COPY default_data.json /opt/taxii/data/default_data.json

RUN cd /opt/taxii/
RUN git clone https://github.com/oasis-open/cti-taxii-server.git src

WORKDIR /opt/taxii/src
CMD [ "medallion", MEDALLION_CONFFILE ] 