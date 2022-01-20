FROM python:3.9

RUN apt update
RUN apt install -y git
RUN apt install -y nginx

COPY ./conf/nginx_medallion.conf /etc/nginx/sites-available/medallion.conf
RUN ln -s /etc/nginx/sites-available/medallion.conf /etc/nginx/sites-enabled/medallion.conf

# Set up the default configuration files
RUN python -m pip install --upgrade pip
RUN pip install --upgrade pip setuptools 
RUN pip install medallion

RUN mkdir -p /opt/taxii/data
RUN mkdir -p /opt/taxii/conf.d
COPY ./conf/medallion.conf /opt/taxii/conf.d/medallion.conf
COPY ./data/default_data.json /opt/taxii/data/default_data.json

RUN cd /opt/taxii/
RUN git clone https://github.com/oasis-open/cti-taxii-server.git src

WORKDIR /opt/taxii/src
COPY ./launch_all.sh /launch_all.sh

RUN echo "daemon off;" >> /etc/nginx/nginx.conf
RUN chmod a+x /launch_all.sh
CMD [ "bash", "-c", "/launch_all.sh" ]