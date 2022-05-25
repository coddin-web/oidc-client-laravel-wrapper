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
    public function execute(bool $public = false): OpenIDConnectClient|OpenIDConnectClientProviderConfigurationPublic
    {
        $appUrl = $this->configRepository->getAsString('app.url');

        $clientClass = match ($public) {
            true => OpenIDConnectClientProviderConfigurationPublic::class,
            false => \Jumbojett\OpenIDConnectClient::class,
        };

        $openIDClient = new $clientClass(
            provider_url: $this->configRepository->getAsString('oidc.provider.endpoint'),
            client_id: $this->configRepository->getAsString('oidc.client.id'),
            client_secret: $this->determineClientSecret(),
            // @phpstan-ignore-next-line The `issuer` parameter is incorrectly typed in the docblock
            issuer: $this->configRepository->getAsString('oidc.provider.issuer'),
        );

        if ($this->configRepository->getAsBool('oidc.client.use_pkce')) {
            $openIDClient->setCodeChallengeMethod('S256');
        }

        $openIDClient->setVerifyHost($this->configRepository->getAsBool('oidc.curl.verify_host'));
        $openIDClient->setVerifyPeer($this->configRepository->getAsBool('oidc.curl.verify_peer'));

        $openIDClient->setRedirectURL(
            url: rtrim($appUrl, '/') . $this->configRepository->getAsString('oidc.client.redirect_url'),
        );

        $openIDClient->addScope($this->configRepository->getAsArray('oidc.client.scopes'));

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
