FROM ubuntu:focal AS nginx-with-shib

ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /tmp

RUN apt-get update -y
RUN apt-get install -y wget curl gnupg2 ca-certificates lsb-release unzip uuid-dev dpkg-dev
RUN echo "deb http://nginx.org/packages/ubuntu focal nginx" | tee /etc/apt/sources.list.d/nginx.list
RUN echo "deb-src http://nginx.org/packages/ubuntu focal nginx" | tee -a /etc/apt/sources.list.d/nginx.list
RUN curl -fsSL https://nginx.org/keys/nginx_signing.key | apt-key add -
RUN apt-get update -y
RUN apt-get source -y nginx=1.20.1
RUN apt-get build-dep -y nginx=1.20.1

RUN wget "https://github.com/samizdatco/nginx-http-auth-digest/archive/master.zip" -O nginx-http-auth-digest.zip
RUN wget "https://github.com/openresty/headers-more-nginx-module/archive/v0.33.tar.gz" -O headers-more-nginx-module-0.33.tar.gz
RUN wget "https://github.com/apache/incubator-pagespeed-ngx/archive/v1.13.35.2-stable.tar.gz" -O incubator-pagespeed-ngx-1.13.35.2-stable.tar.gz
RUN wget "https://github.com/FRiCKLE/ngx_cache_purge/archive/2.3.tar.gz" -O ngx_cache_purge-2.3.tar.gz

RUN unzip nginx-http-auth-digest.zip && \
  tar zxf headers-more-nginx-module-0.33.tar.gz && \
  tar zxvf incubator-pagespeed-ngx-1.13.35.2-stable.tar.gz && \
  tar zxf ngx_cache_purge-2.3.tar.gz

RUN cd /tmp/incubator-pagespeed-ngx-1.13.35.2-stable ; wget https://dl.google.com/dl/page-speed/psol/1.13.35.2-x64.tar.gz ; tar -xzvf 1.13.35.2-x64.tar.gz
RUN sed -i "s#--modules-path=/usr/lib/nginx/modules#--modules-path=/usr/lib/nginx/modules --add-module=/tmp/headers-more-nginx-module-0.33 --add-module=/tmp/nginx-http-auth-digest-master --add-module=/tmp/incubator-pagespeed-ngx-1.13.35.2-stable --add-module=/tmp/ngx_cache_purge-2.3 #g" nginx-1.20.1/debian/rules
RUN cd nginx-1.20.1 && dpkg-buildpackage -b

FROM ubuntu:focal AS nginx-stage_1

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y openssl wget supervisor python3-pip
RUN pip3 install celery flask redis requests uwsgi

WORKDIR /tmp
COPY --from=nginx-with-shib /tmp/nginx_1.20.1-1~focal_amd64.deb .
COPY --from=nginx-with-shib /tmp/nginx-dbg_1.20.1-1~focal_amd64.deb .
RUN dpkg -i nginx_1.20.1-1~focal_amd64.deb

RUN mkdir /var/log/group-management

ADD supervisord.conf /etc/supervisor/supervisord.conf
RUN rm /etc/nginx/conf.d/default.conf
ADD management.conf /etc/nginx/conf.d/
ADD ./keys/server.crt /etc/nginx/cert/server.crt
ADD ./keys/server.key /etc/nginx/cert/server.key

RUN chmod 400 /etc/nginx/cert/server.key

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/supervisord.conf"]