ARG PYTHON_VERSION=2
FROM python:${PYTHON_VERSION}-alpine

COPY nginx-ldap-auth-daemon.py /usr/src/app/

WORKDIR /usr/src/app/

# Install required software
RUN \
    apk --no-cache add openldap-dev && \
    apk --no-cache add --virtual build-dependencies build-base && \
    pip install python-ldap && \
    apk del build-dependencies

EXPOSE 8000

CMD ["python", "/usr/src/app/nginx-ldap-auth-daemon.py",\
     "--host", "0.0.0.0", "--port", "8000"]
