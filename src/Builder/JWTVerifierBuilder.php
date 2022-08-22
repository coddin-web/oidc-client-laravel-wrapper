<?php

declare(strict_types=1);

namespace Coddin\OpenIDConnectClient\Builder;

use Coddin\OpenIDConnectClient\Helper\ConfigRepository;
use Coddin\OpenIDConnectClient\Helper\ConfigRepositoryException;
use Lcobucci\Clock\FrozenClock;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\StrictValidAt;

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
        $signer = new Sha256();
        $key = InMemory::base64Encoded(
            contents: $this->configRepository->getAsString('oidc.private_key.base64'),
        );

        $configuration = Configuration::forSymmetricSigner(
            signer: $signer,
            key: $key,
        );

        $configuration
            ->setValidationConstraints(
                new IssuedBy(
                    id: $this->configRepository->getAsString('oidc.provider.issuer'),
                ),
//                new SignedWith(
//                    signer: $signer,
//                    key: $key,
//                ),
//                new StrictValidAt(
//                    clock: new FrozenClock(new \DateTimeImmutable()),
//                ),
            );

        return $configuration;
    }
}
