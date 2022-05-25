<?php

declare(strict_types=1);

namespace Coddin\OpenIDConnectClient\Builder;

use Jumbojett\OpenIDConnectClient;
use Jumbojett\OpenIDConnectClientException;

/**
 * @codeCoverageIgnore
 */
final class OpenIDConnectClientProviderConfigurationPublic extends OpenIDConnectClient
{
    /**
     * @throws OpenIDConnectClientException
     */
    public function getProviderConfigValuePublic(string $param, ?string $default = null): ?string
    {
        return $this->getProviderConfigValue(param: $param, default: $default);
    }
}
