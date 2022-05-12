<?php

declare(strict_types=1);

namespace Coddin\Tests\Unit\Builder;

use Coddin\OpenIDConnectClient\Builder\OpenIDConnectClientBuilder;
use Coddin\OpenIDConnectClient\Helper\ConfigRepository;
use Jumbojett\OpenIDConnectClient;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

// phpcs:disable PSR1.Methods.CamelCapsMethodName
final class OpenIDConnectClientBuilderTest extends TestCase
{
    /** @var ConfigRepository & MockObject */
    private ConfigRepository|MockObject $configRepository;

    protected function setUp(): void
    {
        $this->configRepository = $this->createPartialMock(
            ConfigRepository::class,
            [
                'getAsString',
                'getAsBool',
            ],
        );
    }

    /** @test */
    public function authorization_code_flow(): void
    {
        $this->configRepository
            ->expects(self::exactly(6))
            ->method('getAsString')
            ->withConsecutive(
                ['app.url'],
                ['oidc.provider.endpoint'],
                ['oidc.client.id'],
                ['oidc.client.secret'],
                ['oidc.provider.issuer'],
                ['oidc.client.redirect_url'],
            )
            ->willReturnOnConsecutiveCalls(
                'https://foo.bar',
                'https://oidc.foobar',
                'client_id',
                'client_secret',
                'https://oidc.foobar',
                'https://redirect.foobar',
            );

        $this->configRepository
            ->expects(self::exactly(4))
            ->method('getAsBool')
            ->withConsecutive(
                ['oidc.client.use_pkce'],
                ['oidc.client.use_pkce'],
                ['oidc.curl.verify_host'],
                ['oidc.curl.verify_peer'],
            )
            ->willReturnOnConsecutiveCalls(
                false,
                false,
                true,
                true,
            );

        $openIdConnectBuilder = new OpenIDConnectClientBuilder(
            configRepository: $this->configRepository,
        );
        /** @noinspection PhpUnhandledExceptionInspection */
        $openIdConnectClient = $openIdConnectBuilder->execute();

        self::assertInstanceOf(OpenIDConnectClient::class, $openIdConnectClient);
        // Obviously this is actually testing the Client, which is beyond our scope,
        // but to maintain certainty it works the way we expect it works within our wrapper
        // we check these values.
        self::assertEquals('https://oidc.foobar', $openIdConnectClient->getProviderURL());
        self::assertEquals('client_id', $openIdConnectClient->getClientID());
        self::assertEquals('client_secret', $openIdConnectClient->getClientSecret());
        self::assertEquals('https://oidc.foobar', $openIdConnectClient->getIssuer());
        self::assertFalse($openIdConnectClient->getCodeChallengeMethod());
    }

    /** @test */
    public function authorization_code_flow_with_PKCE(): void
    {
        $this->configRepository
            ->expects(self::exactly(5))
            ->method('getAsString')
            ->withConsecutive(
                ['app.url'],
                ['oidc.provider.endpoint'],
                ['oidc.client.id'],
                ['oidc.provider.issuer'],
                ['oidc.client.redirect_url'],
            )
            ->willReturnOnConsecutiveCalls(
                'https://foo.bar',
                'https://oidc.foobar',
                'client_id',
                'https://oidc.foobar',
                'https://redirect.foobar',
            );

        $this->configRepository
            ->expects(self::exactly(4))
            ->method('getAsBool')
            ->withConsecutive(
                ['oidc.client.use_pkce'],
                ['oidc.client.use_pkce'],
                ['oidc.curl.verify_host'],
                ['oidc.curl.verify_peer'],
            )
            ->willReturnOnConsecutiveCalls(
                true,
                true,
                true,
                true,
            );

        $openIdConnectBuilder = new OpenIDConnectClientBuilder(
            configRepository: $this->configRepository,
        );
        /** @noinspection PhpUnhandledExceptionInspection */
        $openIdConnectClient = $openIdConnectBuilder->execute();

        self::assertInstanceOf(OpenIDConnectClient::class, $openIdConnectClient);
        // Obviously this is actually testing the Client, which is beyond our scope,
        // but to maintain certainty it works the way we expect it works within our wrapper
        // we check these values.
        self::assertEquals('https://oidc.foobar', $openIdConnectClient->getProviderURL());
        self::assertEquals('client_id', $openIdConnectClient->getClientID());
        self::assertNull($openIdConnectClient->getClientSecret());
        self::assertEquals('https://oidc.foobar', $openIdConnectClient->getIssuer());
        self::assertEquals('S256', $openIdConnectClient->getCodeChallengeMethod());
    }
}
