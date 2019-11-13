FROM arm64v8/debian:stable
ENV DEBIAN_FRONTEND noninteractive
MAINTAINER ba

RUN apt-get -y update && apt-get -y upgrade \
 && apt-get install -yqq openssh-server \
    python3-twisted python3-distutils python3-pip

COPY bromine /bromine/
COPY setup.py tests.py server.py run.sh /
COPY config.ini /root/.config/bromine/config.ini

WORKDIR /
RUN mkdir -pv /run/sshd \
 && python3 -m unittest \
 && groupadd --gid 10000 smith \
 && mkdir -p /home/jerry \
 && useradd -d /home/jerry -M -N --gid 10000 --uid 10000 jerry \
 && chown -R jerry:smith /home/jerry \
 && echo 'jerry:password' | chpasswd \
 && python3 setup.py install
CMD /run.sh
