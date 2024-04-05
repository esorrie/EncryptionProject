FROM python:3.6
ADD . /app
WORKDIR /app
RUN apt-get update && apt-get install -y libgl1-mesa-dev libglu1-mesa-dev
RUN pip install -r requirements.txt