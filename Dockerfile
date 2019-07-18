FROM cartesi/image-emulator-base

MAINTAINER Carlo Fragni <carlo@cartesi.io>

ENV BASE=/opt/machine-manager
ENV EMU_BASE=$BASE/machine-emulator

RUN mkdir $BASE

COPY requirements.txt $BASE/

# Install python and other dependencies
RUN \
    apt-get update && \
    apt-get install -y python3 python3-pip

RUN \
    pip3 install -r $BASE/requirements.txt

COPY . $BASE

#Building the emulator
SHELL ["/bin/bash", "-c"]
RUN \
    cd $EMU_BASE && \
    make distclean && \
    `make env` && \
    make dep && \
    make

#Making grpc/protobuf autogenerated python code files
RUN \
    cd $EMU_BASE/lib/cartesi-grpc && \
    bash generate_python_grpc_code.sh

#Changing directory to base
WORKDIR $BASE
CMD bash -c "cd $EMU_BASE && \`make env\` && cd $BASE && python3 manager_server.py -a 0.0.0.0"
