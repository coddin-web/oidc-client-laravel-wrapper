![build](https://github.com/coddin-web/oidc-client-laravel-wrapper/actions/workflows/main.yml/badge.svg?event=push)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![codecov](https://codecov.io/gh/coddin-web/oidc-client-laravel-wrapper/branch/main/graph/badge.svg?token=U5NCUCX0LH)](https://codecov.io/gh/coddin-web/oidc-client-laravel-wrapper)

# OpenID Connect Client - Laravel wrapper
A Laravel wrapper of jumbojett's OpenID Connect Client ([`jumbojett/openid-connect-php`][1]).

This package will set up a Middleware group that can be used to protect web routes with OpenID Connect
verification and api routes with token verification.

A few things are necessary to make this library work:
- your IDP should support OpenID Connect with OAuth 2(.1) 
- your IDP should have your client already registered
- the application this package is implemented in should have the same private key as your IDP
  - this is needed to verify / parse the JWT

When this package is done verifying the token is legit an Event will be fired to be consumed by the target application.
This event should e.g. perform `Auth::login($user)` to fully let Laravel know this package has handled the authorization.

You can set up an IDP with [`laravel/passport`][2] or set up your own with e.g. a Symfony application in combination with 
[`steverhoades/oauth2-openid-connect-server`][3]

Or better yet use our IDP package which ***is*** a Symfony application with the above-mentioned library fully implemented.
(if we make it public that is...)

[1]: https://github.com/jumbojett/OpenID-Connect-PHP
[2]: https://laravel.com/docs/9.x/passport
[3]: https://github.com/steverhoades/oauth2-openid-connect-server
