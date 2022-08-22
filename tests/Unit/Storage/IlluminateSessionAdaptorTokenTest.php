<?php

declare(strict_types=1);

namespace Coddin\Tests\Unit\Storage;

use Coddin\OpenIDConnectClient\Service\Token\Storage\Exception\MissingTokenException;
use Coddin\OpenIDConnectClient\Service\Token\Storage\IlluminateSessionAdaptorToken;
use Coddin\OpenIDConnectClient\Service\Token\Storage\TokenStorageAdaptor;
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
    public function incorrect_token_type(): void
    {
        $tokenAdaptor = new IlluminateSessionAdaptorToken(
            sessionStore: $this->store,
        );
        $return = $tokenAdaptor->find('not_correct');

        self::assertNull($return);
    }

    /** @test */
    public function missing_token_in_session(): void
    {
        $this->store
            ->expects(self::once())
            ->method('get')
            ->with('oidc_session_key_access_token')
            ->willReturn(null);

        self::expectException(MissingTokenException::class);
        self::expectExceptionMessage('Stored token is not of instance `Lcobucci\JWT\Token`');

        $tokenAdaptor = new IlluminateSessionAdaptorToken(
            sessionStore: $this->store,
        );
        $tokenAdaptor->get(TokenStorageAdaptor::ACCESS_TOKEN_STORAGE_KEY);
    }

    /** @test */
    public function get_token(): void
    {
        $token = $this->createPartialMock(Token::class, []);

        $this->store
            ->expects(self::once())
            ->method('get')
            ->with('oidc_session_key_access_token')
            ->willReturn($token);

        $tokenAdaptor = new IlluminateSessionAdaptorToken(
            sessionStore: $this->store,
        );
        /** @noinspection PhpUnhandledExceptionInspection */
        $tokenAdaptor->get(TokenStorageAdaptor::ACCESS_TOKEN_STORAGE_KEY);
    }

    /** @test */
    public function put_accessToken_only(): void
    {
        $token = $this->createPartialMock(Token::class, []);

        $this->store
            ->expects(self::once())
            ->method('put')
            ->with('oidc_session_key_access_token', $token);

        $tokenAdaptor = new IlluminateSessionAdaptorToken(
            sessionStore: $this->store,
        );
        $tokenAdaptor->put($token);
    }

    /** @test */
    public function put_accessToken_and_refreshToken(): void
    {
        $accessToken = $this->createPartialMock(Token::class, []);
        $refreshToken = 'this_is_a_refresh_token';

        $this->store
            ->expects(self::exactly(2))
            ->method('put')
            ->withConsecutive(
                [
                    'oidc_session_key_access_token',
                    $accessToken,
                ],
                [
                    'oidc_session_key_refresh_token',
                    $refreshToken,
                ],
            );

        $tokenAdaptor = new IlluminateSessionAdaptorToken(
            sessionStore: $this->store,
        );
        $tokenAdaptor->put($accessToken, $refreshToken);
    }

    /** @test */
    public function forget_token(): void
    {
        $this->store
            ->expects(self::exactly(2))
            ->method('forget')
            ->withConsecutive(
                [TokenStorageAdaptor::ACCESS_TOKEN_STORAGE_KEY],
                [TokenStorageAdaptor::REFRESH_TOKEN_STORAGE_KEY],
            );

        $tokenAdaptor = new IlluminateSessionAdaptorToken(
            sessionStore: $this->store,
        );
        $tokenAdaptor->forget();
    }
}
