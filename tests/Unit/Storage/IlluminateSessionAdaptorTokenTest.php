<?php

declare(strict_types=1);

namespace Coddin\Tests\Unit\Storage;

use Coddin\OpenIDConnectClient\Service\Token\Storage\Exception\MissingTokenException;
use Coddin\OpenIDConnectClient\Service\Token\Storage\IlluminateSessionAdaptorToken;
use Illuminate\Session\Store;
use Lcobucci\JWT\Token;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

// phpcs:disable PSR1.Methods.CamelCapsMethodName
final class IlluminateSessionAdaptorTokenTest extends TestCase
{
    /** @var Store & MockObject */
    private Store|MockObject $store;

    protected function setUp(): void
    {
        $this->store = $this->createMock(Store::class);
    }

    /** @test */
    public function missing_token_in_session(): void
    {
        $this->store
            ->expects(self::once())
            ->method('get')
            ->with('oidc_id_token')
            ->willReturn(null);

        self::expectException(MissingTokenException::class);
        self::expectExceptionMessage('Stored token is not of instance `Lcobucci\JWT\Token`');

        $tokenAdaptor = new \Coddin\OpenIDConnectClient\Service\Token\Storage\IlluminateSessionAdaptorToken(
            sessionStore: $this->store,
        );
        $tokenAdaptor->get();
    }

    /** @test */
    public function get_token(): void
    {
        $token = $this->createPartialMock(Token::class, []);

        $this->store
            ->expects(self::once())
            ->method('get')
            ->with('oidc_id_token')
            ->willReturn($token);

        $tokenAdaptor = new \Coddin\OpenIDConnectClient\Service\Token\Storage\IlluminateSessionAdaptorToken(
            sessionStore: $this->store,
        );
        /** @noinspection PhpUnhandledExceptionInspection */
        $tokenAdaptor->get();
    }

    /** @test */
    public function put_token(): void
    {
        $token = $this->createPartialMock(Token::class, []);

        $this->store
            ->expects(self::once())
            ->method('put')
            ->with('oidc_id_token', $token);

        $tokenAdaptor = new IlluminateSessionAdaptorToken(
            sessionStore: $this->store,
        );
        $tokenAdaptor->put($token);
    }

    /** @test */
    public function forget_token(): void
    {
        $this->store
            ->expects(self::once())
            ->method('forget');

        $tokenAdaptor = new IlluminateSessionAdaptorToken(
            sessionStore: $this->store,
        );
        $tokenAdaptor->forget();
    }
}
