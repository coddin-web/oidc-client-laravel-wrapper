<?php

declare(strict_types=1);

namespace Coddin\Tests\Unit\Builder;

use Coddin\OpenIDConnectClient\Builder\JWTVerifierBuilder;
use Coddin\OpenIDConnectClient\Helper\ConfigRepository;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\StrictValidAt;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

// phpcs:disable PSR1.Methods.CamelCapsMethodName
final class JWTVerifierBuilderTest extends TestCase
{
    /** @var ConfigRepository & MockObject */
    private ConfigRepository|MockObject $configRepository;

    protected function setUp(): void
    {
        $this->configRepository = $this->createPartialMock(ConfigRepository::class, ['getAsString']);
    }

    /** @test */
    public function execute(): void
    {
        $this->configRepository
            ->expects(self::exactly(2))
            ->method('getAsString')
            ->withConsecutive(
                ['oidc.private_key.base64'],
                ['oidc.provider.issuer'],
            )
            ->willReturnOnConsecutiveCalls(
                'amVtb2VkZXI=',
                'https://foo.bar',
            );

        $jwtVerifierBuilder = new JWTVerifierBuilder(
            configRepository: $this->configRepository,
        );
        /** @noinspection PhpUnhandledExceptionInspection */
        $jwtVerifier = $jwtVerifierBuilder->execute();

        $constraints = $jwtVerifier->validationConstraints();

        self::assertCount(3, $constraints);

        $expectedNrOfMatches = 3;
        $countedNrOfMatches = 0;
        foreach ($constraints as $constraint) {
            if ($constraint instanceof IssuedBy) {
                $countedNrOfMatches++;
            }
            if ($constraint instanceof SignedWith) {
                $countedNrOfMatches++;
            }
            if ($constraint instanceof StrictValidAt) {
                $countedNrOfMatches++;
            }
        }

        self::assertEquals($expectedNrOfMatches, $countedNrOfMatches, 'The constraint types do not match');
    }
}
