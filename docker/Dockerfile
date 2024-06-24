FROM --platform=linux/amd64 ubuntu:24.04
ENV DEBIAN_FRONTEND noninteractive
RUN apt update -y
RUN apt install curl gpg -y
RUN curl https://download.sep.de/linux/repositories/debian/key.asc | tee /etc/apt/trusted.gpg.d/sepsesam.asc
RUN echo 'deb https://download.sep.de/linux/repositories/debian/ bookworm main' | tee -a /etc/apt/sources.list
RUN apt update -y
RUN apt install sesam-srv python3 -y
COPY start.sh /
RUN chmod +x /start.sh
ENTRYPOINT ["/start.sh"]
