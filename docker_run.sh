#!/bin/bash                                                               

echo "FROM ubuntu:20.04

ENV tinyTLS tinyTLS
ENV TZ=Asia/Seoul
ENV DEBIAN_FRONTEND=\"noninteractive\"

RUN apt update
RUN apt install -y fish emacs-nox openssl curl git 

RUN groupadd -g $(id -g) challenger
RUN useradd -u $(id -u) -g $(id -g) -ms /usr/bin/fish challenger

USER root
WORKDIR /home/challenger

######### Default Settings ###########
ENV LC_CTYPE=C.UTF-8
RUN sed -i 's/archive.ubuntu.com/mirror.kakao.com/g' /etc/apt/sources.list


RUN dpkg --add-architecture i386
RUN apt-get update
RUN apt install -y autoconf libtool pkg-config build-essential gcc-multilib fish vim emacs-nox python3 python3-pip python3-dev libssl-dev libffi-dev gdb gdb-multiarch radare2 git curl wget tmux strace g++
RUN apt install -y libc6-i386 libxml2:i386 libseccomp2:i386
	# binutils:i386


######### Default Settings ###########
##### Install hacker tools #####

USER challenger
WORKDIR /home/challenger

RUN mkdir -p ~/.pip
RUN /bin/bash -c 'git clone https://github.com/oh-my-fish/oh-my-fish ; cd oh-my-fish ; fish ~/oh-my-fish/bin/install --offline --noninteractive --yes'
RUN rm -rf ~/oh-my-fish
RUN git clone https://github.com/longld/peda.git ~/.peda
RUN echo \"set auto-load safe-path /\" >> ~/.gdbinit
RUN wget -O ~/.gdbinit-gef.py -q https://github.com/hugsy/gef/raw/master/gef.py
RUN echo source ~/.gdbinit-gef.py >> ~/.gdbinit

#COPY proc.py /home/challenger/.local/lib/python3.7/site-packages/pwnlib/util/proc.py

RUN echo \"##### THIS IS DUMMY FLAG #####\" > /home/challenger/.dummy_flag


######### Challenge Specifics ###########
USER root

######### Launch ###########
USER root
SHELL [\"fish\", \"--command\"]
RUN chsh -s /usr/bin/fish
ENV SHELL /usr/bin/bash

COPY ./entry-point.sh /usr/bin/entry-point.sh
RUN chmod +x /usr/bin/entry-point.sh
ENTRYPOINT [ \"/usr/bin/entry-point.sh\" ]
" > Dockerfile

docker build -t midterm:tinyTLS ./
docker run -it -v $(pwd):/home/challenger/tinyTLS:rw midterm:tinyTLS