<?php

declare(strict_types=1);

namespace Coddin\OpenIDConnectClient\Builder;

use Illuminate\Support\Facades\Config;
use Jumbojett\OpenIDConnectClient;

final class OpenIDConnectClientBuilder
{
    public function execute(): OpenIDConnectClient
    {
        $openIDClient = new \Jumbojett\OpenIDConnectClient(
            provider_url: Config::get('oidc.provider.endpoint'),
            client_id: Config::get('oidc.client.id'),
            client_secret: Config::get('oidc.client.use_pkce') ? null : Config::get('oidc.client.secret'),
            // @phpstan-ignore-next-line The `issuer` parameter is incorrectly typed in the docblock
            issuer: Config::get('oidc.provider.issuer'),
        );

        if (Config::get('oidc.client.use_pkce')) {
            $openIDClient->setCodeChallengeMethod('S256');
        }

        $appUrl = Config::get('app.url');
        if (!is_string($appUrl)) {
            throw new \LogicException('The `app.url` config value is malformed, it should be a string');
        }

        $openIDClient->setRedirectURL(
            url: rtrim($appUrl, '/') . Config::get('oidc.client.redirect_url'),
        );

        return $openIDClient;
    }
}
