Quick Start
===========

Running mailgoose locally
-------------------------
To run the service locally, use:

.. code-block:: console

    git clone https://github.com/CERT-Polska/mailgoose

    cd mailgoose

    cp env.example .env  # After doing that, customize the settings in .env if needed

    docker compose up --build

The application will listen on http://127.0.0.1:8000 .

To start the application, you need to configure only the variables present in
``env.example`` - all others are optional. To learn what settings are available,
please refer to :doc:`user-guide/configuration`.

To send a test e-mail to a local instance of Mailgoose from the terminal, you may use Python
``smtplib`` library:

.. code-block:: python

    import smtplib

    server = smtplib.SMTP('localhost')
    server.sendmail(
        "example@example.com",
        recipient_address, # put here the proper recipient address
        "From: example@example.com\r\nhello"
    )
    server.quit()

Production deployment
---------------------
Before deploying the system to production, remember:

- that the ``mail_receiver`` container is responsible for saving incoming mails to
  Redis - make sure ports 25 and 587 are exposed publicly so that mailgoose will be able
  to receive a test e-mail. Make sure the domain configured in the ``APP_DOMAIN`` setting has ``MX`` DNS
  records pointing to the server ``mail_receiver`` is running on,
- that the domain your system is listening on should not use CNAME records - this is not allowed by the RFCs and it causes multiple random issues, e.g. related to DKIM validation,
- that SMTP SSL is supported - please refer to ``SSL_CERTIFICATE_PATH`` and ``SSL_PRIVATE_KEY_PATH``
  settings documentation in :doc:`user-guide/configuration` to learn how to set it up,
- to change the database password to a more secure one and to use Redis password (or make sure
  the database and Redis are isolated on the network),
- to decide whether you want to launch a database/Redis instance inside a container or
  e.g. attaching to your own PostgreSQL/Redis cluster,
- to check whether you want to use Google nameservers or other ones.

Instead of copying ``docker-compose.yml``, you may override the configuration using the
``docker compose -f docker-compose.yml -f docker-compose.override.yml`` syntax.

Changing the layout
-------------------
If you want to change the main layout template (e.g. to provide additional scripts or your own
custom navbar with logo), mount a different file using Docker to ``/app/templates/custom_layout.html``.
Refer to ``app/templates/base.html`` to learn what block you can fill.

You can also customize the root page (/) of the system by providing your own file that will
replace ``/app/templates/custom_root_layout.html``.

By replacing ``/app/templates/custom_failed_check_result_hints.html`` you may provide your own
text that will be displayed if the e-mail sender verification mechanisms checks fail (for example
to provide links to tutorials).

At CERT PL we use a separate ``docker-compose.yml`` file with additional configuration
specific to our instance (https://bezpiecznapoczta.cert.pl/). Instead of copying
``docker-compose.yml``, we override the configuration using the
``docker compose -f docker-compose.yml -f docker-compose.override.yml`` syntax.
