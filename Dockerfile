FROM ubuntu:20.04

RUN apt-get update -y && apt-get install -y build-essential curl clang-format git python3 python3-pip
RUN pip3 install --upgrade pip && pip3 install pre-commit

ARG CMAKE_VERSION=3.10
RUN curl -SL https://cmake.org/files/v$CMAKE_VERSION/cmake-$CMAKE_VERSION.0-Linux-x86_64.tar.gz |tar -xz --strip-components=1 -C /usr/local
