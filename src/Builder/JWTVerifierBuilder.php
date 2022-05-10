<?php

declare(strict_types=1);

namespace Coddin\OpenIDConnectClient\Builder;

use Coddin\OpenIDConnectClient\Builder\Exception\JWTVerifierBuilderException;
use Illuminate\Support\Facades\Config;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;

final class JWTVerifierBuilder
{
    /**
     * @throws JWTVerifierBuilderException
     */
    public function execute(): Configuration
    {
        $privateKeyPath = Config::get('oidc.cert.path');

        if (!is_string($privateKeyPath)) {
            throw JWTVerifierBuilderException::invalidPrivateKeyPath($privateKeyPath);
        }

        return Configuration::forSymmetricSigner(
            new Sha256(),
            InMemory::file($privateKeyPath),
        );
    }
}
