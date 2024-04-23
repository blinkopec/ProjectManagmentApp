FROM python:3.11.8-alpine

ENV PYTHONUNBUFFERED 1
ENV PYTHONDONTWRITEBYTECODE 1

WORKDIR /diplom2/backend

COPY requirements.txt /diplom2/backend/

RUN pip install --upgrade pip
# Build psycopg2-binary from source -- add required required dependencies
RUN apk add --virtual .build-deps --no-cache postgresql-dev gcc python3-dev musl-dev && \
        pip install --no-cache-dir -r requirements.txt && \
        apk --purge del .build-deps

COPY . /diplom2/backend/

CMD [ "python", "manage.py", "runserver", "0.0.0.0:8000" ]
