FROM php:8.1-fpm

COPY .env /var/www/html/.env
COPY . /var/www/html

RUN apt-get update && apt-get install -y libpq-dev \
    && docker-php-ext-install pdo pdo_pgsql

WORKDIR /var/www/html

EXPOSE 9000
