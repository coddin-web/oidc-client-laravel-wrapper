<?php

declare(strict_types=1);

namespace Coddin\OpenIDConnectClient\Builder;

use Coddin\OpenIDConnectClient\Helper\ConfigRepository;
use Coddin\OpenIDConnectClient\Helper\ConfigRepositoryException;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Validation\Constraint\IdentifiedBy;

final class JWTVerifierBuilder
{
    public function __construct(
        private readonly ConfigRepository $configRepository,
    ) {
    }

    /**
     * @throws ConfigRepositoryException
     */
    public function execute(): Configuration
    {
        $configuration = Configuration::forSymmetricSigner(
            new Sha256(),
            InMemory::base64Encoded(
                $this->configRepository->getAsString('oidc.private_key.base64'),
            ),
        );

        $configuration
            ->setValidationConstraints(
                new IdentifiedBy(
                    $this->configRepository->getAsString('oidc.provider.issuer'),
                ),
            );

        return $configuration;
    }
}
