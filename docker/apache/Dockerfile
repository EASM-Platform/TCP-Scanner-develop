FROM httpd:2.4

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/* \
    && sed -i 's/^#LoadModule ssl_module modules\/mod_ssl.so/LoadModule ssl_module modules\/mod_ssl.so/' /usr/local/apache2/conf/httpd.conf \
    && sed -i 's/^#LoadModule socache_shmcb_module modules\/mod_socache_shmcb.so/LoadModule socache_shmcb_module modules\/mod_socache_shmcb.so/' /usr/local/apache2/conf/httpd.conf \
    && sed -i 's/^#LoadModule headers_module modules\/mod_headers.so/LoadModule headers_module modules\/mod_headers.so/' /usr/local/apache2/conf/httpd.conf \
    && sed -i 's/^#Include conf\/extra\/httpd-ssl.conf/Include conf\/extra\/httpd-ssl.conf/' /usr/local/apache2/conf/httpd.conf \
    && printf '\nServerName easm-web\nInclude conf/extra/easm-httpd.conf\n' >> /usr/local/apache2/conf/httpd.conf

COPY easm-httpd.conf /usr/local/apache2/conf/extra/easm-httpd.conf
COPY httpd-ssl.conf /usr/local/apache2/conf/extra/httpd-ssl.conf
COPY run-httpd.sh /usr/local/bin/run-httpd.sh
COPY index.html /usr/local/apache2/htdocs/index.html

RUN chmod +x /usr/local/bin/run-httpd.sh

EXPOSE 80 443

CMD ["/usr/local/bin/run-httpd.sh"]
