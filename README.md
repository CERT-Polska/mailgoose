# mailgoose

## How to run locally
To run the service locally, use:

```
cp env.example .env
# Please review the file and set the configuration variables as needed,
# especially APP_DOMAIN - the domain you will serve the application on.
#
# You may provide additional settings in this file, e.g. SSL certificate
# settings: SSL_PRIVATE_KEY_PATH and SSL_CERTIFICATE_PATH.

docker compose up --build
```

The application will listen on http://127.0.0.1:8000

## How to deploy to production
Before deploying the system using the configuration in `docker-compose.yml` remember to:

- change the database password to a more secure one,
- use Redis password,
- consider whether you want to launch a database/Redis instance inside a container (instead
  of e.g. attaching to your own PostgreSQL cluster),
- check whether you want to use Google nameservers.

Instead of copying `docker-compose.yml`, you may override the configuration using the
`docker compose -f docker-compose.yml -f docker-compose.override.yml` syntax.

## How to change the layout
If you want to change the main layout template (e.g. to provide additional scripts or your own
custom navbar with logo), mount a different file using Docker to `/app/templates/custom_layout.html`.
Refer to `app/templates/base.html` to learn what block you can fill.

You can also customize the root page (/) of the system by providing your own file that will
replace `/app/templates/custom_root_layout.html`.

By replacing `/app/templates/custom_failed_check_result_hints.html` you may provide your own
text that will be displayed if the e-mail sender verification mechanisms checks fail.

At CERT PL we use a separate `docker-compose.yml` file with additional configuration
specific to our instance (https://bezpiecznapoczta.cert.pl/). Instead of copying
`docker-compose.yml`, we override the configuration using the
`docker compose -f docker-compose.yml -f docker-compose.override.yml` syntax.

## How to use the HTTP API

To check a domain using a HTTP API, use:

```
curl -X POST http://127.0.0.1:8000/api/v1/check-domain?domain=example.com
```

## How to run the tests
To run the tests, use:

```
./script/test
```
