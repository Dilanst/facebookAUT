FROM ubuntu

MAINTAINER  Author Name <Dlsteeven@hotmail.com>

RUN apt-get update && \
    apt-get install -y software-properties-common python-software-properties && \
	add-apt-repository ppa:webupd8team/java && \
	apt-get update
	
RUN echo "oracle-java8-installer shared/accepted-oracle-license-v1-1 select true" | debconf-set-selections && \
	echo "oracle-java8-installer shared/accepted-oracle-license-v1-1 seen true" | debconf-set-selections && \
    apt-get install -y oracle-java8-set-default
	
RUN apt-get install -y \
        git \
        maven 

WORKDIR Preproduccion

ADD Facebook /Preproduccion

EXPOSE 8080

RUN   mvn  clean install

CMD   tail -f /dev/null 
