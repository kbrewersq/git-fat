FROM --platform=linux/amd64 python:2.7.16

RUN apt-get update && \
    apt-get install -y python-pip python-dev build-essential git curl \
    && rm -rf /var/lib/apt/lists/*

RUN curl https://raw.githubusercontent.com/kbrewersq/git-fat/main/git_fat/git_fat.py | tee bin/git-fat && chmod +x bin/git-fat


LABEL run_type="gitfatworld"
ENV GIT_BRANCH master
COPY /s3_requirements.txt /s3_requirements.txt
RUN pip install -r /s3_requirements.txt


## configure the rest of your docker container here
## run with -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY 
## with optional -e AWS_SESSION_TOKEN
# docker build --no-cache -t gitfatworld . 
# docker run --rm -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_SESSION_TOKEN gitfatworld