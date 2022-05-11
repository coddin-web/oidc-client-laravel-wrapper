<?php

declare(strict_types=1);

namespace Coddin\OpenIDConnectClient\Builder;

use Coddin\OpenIDConnectClient\Helper\ConfigRepository;
use Coddin\OpenIDConnectClient\Helper\ConfigRepositoryException;
use Jumbojett\OpenIDConnectClient;

final class OpenIDConnectClientBuilder
{
    public function __construct(
        private readonly ConfigRepository $configRepository,
    ) {
    }

    /**
     * @throws ConfigRepositoryException
     */
    public function execute(): OpenIDConnectClient
    {
        $appUrl = $this->configRepository->getAsString('app.url');

        $openIDClient = new \Jumbojett\OpenIDConnectClient(
            provider_url: $this->configRepository->getAsString('oidc.provider.endpoint'),
            client_id: $this->configRepository->getAsString('oidc.client.id'),
            client_secret: $this->determineClientSecret(),
            // @phpstan-ignore-next-line The `issuer` parameter is incorrectly typed in the docblock
            issuer: $this->configRepository->getAsString('oidc.provider.issuer'),
        );

        if ($this->configRepository->getAsBool('oidc.client.use_pkce')) {
            $openIDClient->setCodeChallengeMethod('S256');
        }

        $openIDClient->setRedirectURL(
            url: rtrim($appUrl, '/') . $this->configRepository->getAsString('oidc.client.redirect_url'),
        );

        return $openIDClient;
    }

    /**
     * @throws ConfigRepositoryException
     */
    private function determineClientSecret(): ?string
    {
        return $this->configRepository->getAsBool('oidc.client.use_pkce')
            ? null
            : $this->configRepository->getAsString('oidc.client.secret');
    }
}