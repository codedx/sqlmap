# testenv

The name "testenv" refers to the [sqlmap sample project by the same name](https://github.com/sqlmapproject/testenv) which starts a PHP-based web server and supports many database types. We ran this via Docker based on a modified version of the `Dockerfile` provided. Our changes are available in the "Dockerfile Updates" section below. We used the name `testenv:v1.0` when building the image locally.

Note that the original Dockerfile only exposes a MySQL-based server; the various other database types in the `testenv` project are not exposed.

## Running the app

```
docker run --name testenv --rm -d -p 80:80 testenv:v1.0
```

This will run the application and expose it on port 80. The base path for the application will be `http://localhost/sqlmap`.

## Sample commands

We used the sqlmap commands below when testing against testenv. Note that since MySQL is the only DB backend supported on the docker image, our tests only target from `/sqlmap/mysql`.

### Crawl and batch scan

```
python sqlmap.py \
    -u http://localhost/sqlmap/mysql/ \
    --batch \
    --crawl=3 \
    --dbms=MySQL \
    --answers="skip=N"
```

### Targetted scan for affixes

```
python sqlmap.py \
    -u http://minikube.local/sqlmap/mysql/get_str_brackets.php?id=1
    --dbms=MySQL
    -p id
    --prefix "')"
    --suffix "AND ('abc'='abc"
```

## Dockerfile Updates

At the time of writing (June 25, 2020), the Dockerfile provided on the project no longer builds and must be updated. For our testing, cloning that repository and replacing the Dockerfile with the following worked:

```
FROM debian:jessie

# Updating base system
RUN apt-get update
RUN apt-get upgrade -y

# Installing Apache, PHP, git and generic PHP modules
RUN DEBIAN_FRONTEND=noninteractive apt-get -qq -y install apache2 libapache2-mod-php5 git php5-dev php5-gd php-pear \
                       php5-mysql php5-pgsql php5-sqlite php5-interbase php5-sybase \
                       php5-odbc unzip make libaio1 bc screen htop git \
                       subversion sqlite sqlite3 mysql-server mysql-client libmysqlclient-dev \
                       netcat libssl-dev libtool zlib1g-dev libc6-dev

# Configuring Apache and PHP
RUN if [ -e /var/www/html/index.html ]; then rm /var/www/html/index.html; fi
RUN mkdir /var/www/html/test
RUN chmod 777 /var/www/html/test
RUN a2enmod auth_basic auth_digest
RUN sed -i 's/AllowOverride None/AllowOverride AuthConfig/' /etc/apache2/sites-enabled/*
RUN sed -i 's/magic_quotes_gpc = On/magic_quotes_gpc = Off/g' /etc/php5/*/php.ini

# Copy sqlmap test environment to /var/www
COPY . /var/www/html/sqlmap/
WORKDIR /var/www/html/sqlmap

# Listen on port 80
EXPOSE 80

CMD ["/var/www/html/sqlmap/docker/run.sh"]
```

The image could then be built with:

```
cd testenv
docker build -t testenv:v1.0 .
```

Primary changes are:

- Switch from `debian:wheezy` to `debian:jessie` base image, as `wheezy` is no longer supported and the required packages could not be resolved
- Update file copy location for webserver contents from `/var/www/sqlmap` to `/var/www/html/sqlmap`

Note that our changes may also be outdated soon, as the `debian:jessie` base image we used is also very old.