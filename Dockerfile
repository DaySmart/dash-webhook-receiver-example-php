# syntax=docker/dockerfile:1
FROM php:8.5-fpm-alpine AS base

# Install system dependencies and PHP extensions
RUN apk --no-cache upgrade \
    && apk add --no-cache \
        oniguruma-dev \
        libzip-dev \
        zip \
        unzip \
    && docker-php-ext-install pdo pdo_mysql mbstring zip

WORKDIR /var/www/html

COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["php-fpm"]

# ---------------------------------------------------------------------------
# dev: Xdebug + full (dev) Composer dependencies, unoptimised autoloader.
# Used by docker-compose for local development; the source tree is bind
# mounted over this at runtime, so the COPY/composer install below just
# make `docker build --target dev .` usable on its own too.
# ---------------------------------------------------------------------------
FROM base AS dev

RUN apk add --no-cache --virtual .build-deps $PHPIZE_DEPS linux-headers \
    && pecl install xdebug \
    && docker-php-ext-enable xdebug \
    && apk del .build-deps

COPY docker/xdebug.ini /usr/local/etc/php/conf.d/xdebug.ini

COPY . .

RUN --mount=type=bind,from=composer:2,source=/usr/bin/composer,target=/usr/bin/composer \
  composer install --no-interaction --prefer-dist

RUN chown -R www-data:www-data storage bootstrap/cache

# ---------------------------------------------------------------------------
# production (default target): no dev dependencies, optimized autoloader.
# ---------------------------------------------------------------------------
FROM base AS production

COPY . .

RUN --mount=type=bind,from=composer:2,source=/usr/bin/composer,target=/usr/bin/composer \
  composer install --no-dev --optimize-autoloader --no-interaction --prefer-dist

RUN chown -R www-data:www-data storage bootstrap/cache
