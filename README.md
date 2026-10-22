# CasAuthBundle
Basic CAS (SSO) authenticator for Symfony

This bundle provides a -very- basic CAS (http://jasig.github.io/cas/4.1.x/index.html) authentication client for Symfony.

Requirements: PHP >= 8.2 and Symfony >= 5.4 (tested up to Symfony 7).

## Installation

Install the library via [Composer](https://getcomposer.org/) by
running the following command:

```bash
composer require prayno/casauth-bundle
```

If you don't use Symfony Flex, enable the bundle in your `config/bundles.php` file:

```php
<?php
// config/bundles.php

return [
    // ...
    PRayno\CasAuthBundle\PRaynoCasAuthBundle::class => ['all' => true],
];
```

In `config/packages/p_rayno_cas_auth.yaml` (create this file), add these settings:
```yaml
p_rayno_cas_auth:
    server_login_url: https://mycasserver/cas/
    server_validation_url: https://mycasserver/cas/serviceValidate
    server_logout_url: https://mycasserver/cas/logout
    xml_namespace: cas
    options: [] # see http://docs.guzzlephp.org/en/latest/request-options.html
```
Note : the xml_namespace and options parameters are optional

Modify your `security.yaml` with the following values (the provider in the following settings should not be used as it's just a very basic example ; in production, create your own UserProvider and add it in `prayno.cas_authenticator`'s `$userProvider` argument, see below) :
```yaml
security:
    # Only needed on Symfony 5.4 ; the authenticator system is the only one
    # available from Symfony 6.0 onwards and this option no longer exists.
    enable_authenticator_manager: true

    providers:
        cas:
          id: prayno.cas_user_provider

    firewalls:
        dev:
            pattern: ^/(_(profiler|wdt)|css|images|js)/
            security: false
        main:
            provider: cas
            logout: ~
            custom_authenticators:
                - prayno.cas_authenticator

    access_control:
        - { path: ^/, roles: ROLE_USER }
  ```

  And voila ! Your secured route should redirect you to your CAS login page which should authenticate you.

### Using your own UserProvider

The default `prayno.cas_user_provider` service is just a demo provider that grants `ROLE_USER` without checking anything else. To use your own provider, implement
`Symfony\Component\Security\Core\User\UserProviderInterface` (or `PRayno\CasAuthBundle\Security\User\CasUserProviderInterface` if you need access to the CAS attributes released by your CAS server), register it as a service, and point the authenticator at it :

```yaml
# config/services.yaml
services:
    prayno.cas_authenticator:
        arguments:
            $userProvider: '@App\Security\MyCasUserProvider'
```

## CAS global logout option

If you want your users to logout from the remote CAS server when logging out from your app, register the bundled logout event subscriber :

```yaml
# config/services.yaml
services:
    PRayno\CasAuthBundle\Event\LogoutSuccessHandler:
        arguments:
            $logoutUrl: "%cas_logout_url%"
```

Of course, you must set a "cas_logout_url" parameter in your app (eg. https://my_remote_cas_server/logout)

Don't forget to define a /logout route in your app (via the `logout:` key on your firewall, see the `security.yaml` example above).

Note: this subscriber reacts to every `LogoutEvent` dispatched by the application, so if you have several firewalls with a `logout:` section, they will all redirect to the same CAS logout URL.
