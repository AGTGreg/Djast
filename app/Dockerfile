FROM python:3.12-slim

# Variables
ENV PYTHONUNBUFFERED 1
ENV APP_HOME=/app

# Create a user
RUN useradd -ms /bin/bash appuser

# Create a directory for our app and move inside.
RUN mkdir -p ${APP_HOME}
WORKDIR ${APP_HOME}

# Create the static, media and logs shared volume directories
RUN mkdir -p /vol/app/media
RUN mkdir -p /vol/app/static
RUN mkdir -p /vol/app/logs

# Give ownership of the app dir to the appuser
RUN chown -R appuser:appuser ${APP_HOME}
RUN chown -R appuser:appuser /vol
RUN chmod -R 755 /vol/app

# Install system packages
RUN apt-get update \
    && apt-get install -y --fix-missing build-essential libpq-dev gcc

# Install system and pip dependencies.
COPY ./requirements.txt ${APP_HOME}/requirements.txt
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

# Switch to our user
USER appuser

CMD [ "fastapi", "dev", "main.py", "--host", "0.0.0.0", "--reload" ]