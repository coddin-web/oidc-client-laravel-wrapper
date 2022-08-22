<?php

/** @noinspection PhpMissingFieldTypeInspection */

declare(strict_types=1);

namespace Coddin\Tests\Unit\Http\Middleware;

use Coddin\OpenIDConnectClient\Builder\JWTVerifierBuilder;
use Coddin\OpenIDConnectClient\Builder\OpenIDConnectClientBuilder;
use Coddin\OpenIDConnectClient\Event\UserAuthorizedEvent;
use Coddin\OpenIDConnectClient\Helper\ConfigRepository;
use Coddin\OpenIDConnectClient\Helper\ConfigRepositoryException;
use Coddin\OpenIDConnectClient\Http\Middleware\OpenIDConnectAuthenticated;
use Coddin\OpenIDConnectClient\Service\Token\Storage\TokenStorageAdaptor;
use Coddin\Tests\Helper\ClosureTestClass;
use Illuminate\Http\Request;
use Illuminate\Routing\ResponseFactory;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Log;
use Jumbojett\OpenIDConnectClient;
use Jumbojett\OpenIDConnectClientException;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\DataSet;
use Lcobucci\JWT\Token\Parser;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\MockObject\MockObject;
use Symfony\Component\HttpKernel\Exception\HttpException;

// phpcs:disable PSR1.Methods.CamelCapsMethodName
final class OpenIDConnectAuthenticatedTest extends TestCase
{
    /** @var ResponseFactory & MockObject */
    private $responseFactory;
    /** @var OpenIDConnectClientBuilder & MockObject */
    private $openIDConnectClientBuilder;
    /** @var JWTVerifierBuilder & MockObject */
    private $jwtVerifierBuilder;
    /** @var TokenStorageAdaptor & MockObject */
    private $storageAdaptor;
    /** @var ConfigRepository & MockObject */
    private $configRepository;

    /** @var Request & MockObject */
    private $request;
    /** @var ClosureTestClass & MockObject */
    private $closure;

    protected function setUp(): void
    {
        parent::setUp();

        $this->responseFactory = $this->createMock(ResponseFactory::class);
        $this->openIDConnectClientBuilder = $this->createPartialMock(OpenIDConnectClientBuilder::class, ['execute']);
        $this->jwtVerifierBuilder = $this->createPartialMock(JWTVerifierBuilder::class, ['execute']);
        $this->storageAdaptor = $this->createMock(TokenStorageAdaptor::class);
        $this->configRepository = $this->createPartialMock(ConfigRepository::class, ['getAsString']);

        $this->request = $this->createMock(Request::class);
        $this->closure = $this->createMock(ClosureTestClass::class);
    }

    /** @test */
    public function logout_ignore(): void
    {
        $this->request
            ->expects(self::once())
            ->method('getPathInfo')
            ->willReturn('/logout');

        $openIDConnectAuthenticated = $this->createOpenIDConnectAuthenticated();
        $this->handle($openIDConnectAuthenticated);
    }

    /** @test */
    public function existing_token_expired(): void
    {
        $accessToken = $this->createMock(Token::class);
        $accessToken
            ->expects(self::once())
            ->method('isExpired')
            ->willReturn(true);

        $this->storageAdaptor
            ->expects(self::once())
            ->method('find')
            ->with(TokenStorageAdaptor::ACCESS_TOKEN_STORAGE_KEY)
            ->willReturn($accessToken);

        $this->storageAdaptor
            ->expects(self::once())
            ->method('forget');

        $this->responseFactory
            ->expects(self::once())
            ->method('redirectTo')
            ->with('/foobar');

        $this->request
            ->expects(self::exactly(2))
            ->method('getPathInfo')
            ->willReturn('/foobar');

        $openIDConnectAuthenticated = $this->createOpenIDConnectAuthenticated();
        $this->handle($openIDConnectAuthenticated, false);
    }

    /** @test */
    public function existing_token_still_valid(): void
    {
        $accessToken = $this->createPartialMock(Token\Plain::class, ['isExpired', 'claims']);
        $accessToken
            ->expects(self::once())
            ->method('isExpired')
            ->willReturn(false);

        $this->storageAdaptor
            ->expects(self::once())
            ->method('find')
            ->with(TokenStorageAdaptor::ACCESS_TOKEN_STORAGE_KEY)
            ->willReturn($accessToken);

        $now = new \DateTimeImmutable();
        $issuedAt = clone $now;
        $expiresAt = (clone $now)->add(new \DateInterval('PT60M'));
        $claims = new DataSet(
            data: [
                'iat' => $issuedAt,
                'exp' => $expiresAt,
            ],
            encoded: 'encoded_string',
        );
        $accessToken
            ->expects(self::once())
            ->method('claims')
            ->willReturn($claims);

        $openIDConnectAuthenticated = $this->createOpenIDConnectAuthenticated();
        $this->handle($openIDConnectAuthenticated);
    }

    /** @test */
    public function existing_token_almost_expired(): void
    {
        $accessToken = $this->createPartialMock(Token\Plain::class, ['isExpired', 'claims']);
        $accessToken
            ->expects(self::once())
            ->method('isExpired')
            ->willReturn(false);

        $this->storageAdaptor
            ->expects(self::once())
            ->method('find')
            ->with(TokenStorageAdaptor::ACCESS_TOKEN_STORAGE_KEY)
            ->willReturn($accessToken);

        $now = new \DateTimeImmutable();
        $issuedAt = (clone $now)->sub(new \DateInterval('PT50M'));
        $expiresAt = clone $now;
        $claims = new DataSet(
            data: [
                'iat' => $issuedAt,
                'exp' => $expiresAt,
            ],
            encoded: 'encoded_string',
        );
        $accessToken
            ->expects(self::once())
            ->method('claims')
            ->willReturn($claims);

        $refreshToken = $this->createPartialMock(Token\Plain::class, ['toString']);
        $this->storageAdaptor
            ->expects(self::once())
            ->method('get')
            ->with(TokenStorageAdaptor::REFRESH_TOKEN_STORAGE_KEY)
            ->willReturn($refreshToken);

        $refreshToken
            ->expects(self::once())
            ->method('toString')
            ->willReturn('this_is_a_refresh_token');

        $openIDConnectClient = $this->createMock(OpenIDConnectClient::class);
        $this->openIDConnectClientBuilder
            ->expects(self::once())
            ->method('execute')
            ->willReturn($openIDConnectClient);

        $openIDConnectClient
            ->expects(self::once())
            ->method('refreshToken')
            ->with('this_is_a_refresh_token');

        $jwtVerifier = $this->createPartialMock(Configuration::class, ['parser']);
        $this->jwtVerifierBuilder
            ->expects(self::once())
            ->method('execute')
            ->willReturn($jwtVerifier);

        /** @var Parser & MockObject $parser */
        $parser = $this->createPartialMock(Parser::class, ['parse']);
        $jwtVerifier
            ->expects(self::once())
            ->method('parser')
            ->willReturn($parser);

        $openIDConnectClient
            ->expects(self::once())
            ->method('getIdToken')
            ->willReturn('this_is_an_access_token');

        $newAccessToken = $this->createMock(Token::class);
        $parser
            ->expects(self::once())
            ->method('parse')
            ->with('this_is_an_access_token')
            ->willReturn($newAccessToken);

        $openIDConnectClient
            ->expects(self::once())
            ->method('getRefreshToken')
            ->willReturn('this_is_a_refresh_token');

        $this->storageAdaptor
            ->expects(self::once())
            ->method('put')
            ->with($newAccessToken, 'this_is_a_refresh_token');

        $openIDConnectAuthenticated = $this->createOpenIDConnectAuthenticated();
        $this->handle($openIDConnectAuthenticated);
    }

    /** @test */
    public function open_ID_client_exception(): void
    {
        $this->storageAdaptor
            ->expects(self::once())
            ->method('find')
            ->willReturn(null);

        $this->jwtVerifierBuilder
            ->expects(self::once())
            ->method('execute');

        $openIDClient = $this->createMock(OpenIDConnectClient::class);
        $this->openIDConnectClientBuilder
            ->expects(self::once())
            ->method('execute')
            ->willReturn($openIDClient);

        $openIDClient
            ->expects(self::once())
            ->method('authenticate')
            ->willThrowException(new OpenIDConnectClientException('this_is_a_message'));

        Log::shouldReceive('error')
            ->with('Authenticating the OpenIDConnect Client failed:');

        Log::shouldReceive('error')
            ->withSomeOfArgs('this_is_a_message');

        self::expectException(HttpException::class);

        $openIDConnectAuthenticated = $this->createOpenIDConnectAuthenticated();
        $this->handle($openIDConnectAuthenticated, false);
    }

    /** @test */
    public function configRepository_exception(): void
    {
        $this->storageAdaptor
            ->expects(self::once())
            ->method('find')
            ->willReturn(null);

        $this->jwtVerifierBuilder
            ->expects(self::once())
            ->method('execute')
            ->willThrowException(new ConfigRepositoryException('This is a message'));

        Log::shouldReceive('error')
            ->withSomeOfArgs('This is a message');

        self::expectException(HttpException::class);

        $openIDConnectAuthenticated = $this->createOpenIDConnectAuthenticated();
        $this->handle($openIDConnectAuthenticated, false);
    }

    private function authenticateWithNewToken(): void
    {
        $this->storageAdaptor
            ->expects(self::once())
            ->method('find')
            ->willReturn(null);

        $jwtVerifier = $this->createPartialMock(Configuration::class, ['parser']);
        $this->jwtVerifierBuilder
            ->expects(self::once())
            ->method('execute')
            ->willReturn($jwtVerifier);

        $openIDClient = $this->createMock(OpenIDConnectClient::class);
        $this->openIDConnectClientBuilder
            ->expects(self::once())
            ->method('execute')
            ->willReturn($openIDClient);

        $openIDClient
            ->expects(self::once())
            ->method('authenticate');

        $parser = $this->createPartialMock(Parser::class, ['parse']);
        $jwtVerifier
            ->expects(self::once())
            ->method('parser')
            ->willReturn($parser);

        $openIDClient
            ->expects(self::once())
            ->method('getIdToken')
            ->willReturn('id_token.second_part.third_part');

        $dataSet = $this->createPartialMock(DataSet::class, ['get']);
        $dataSet
            ->expects(self::exactly(3))
            ->method('get')
            ->withConsecutive(
                ['sub'],
                ['nickname'],
                ['email'],
            )
            ->willReturnOnConsecutiveCalls(
                'uuid',
                'name',
                'email@test.test',
            );

        $idToken = $this->createPartialMock(Token\Plain::class, ['claims']);
        $idToken
            ->expects(self::exactly(3))
            ->method('claims')
            ->willReturn($dataSet);

        $parser
            ->expects(self::once())
            ->method('parse')
            ->withConsecutive(
                ['id_token.second_part.third_part'],
            )
            ->willReturnOnConsecutiveCalls(
                $idToken,
            );

        $refreshToken = 'asdf';
        $openIDClient
            ->expects(self::once())
            ->method('getRefreshToken')
            ->willReturn($refreshToken);

        $this->storageAdaptor
            ->expects(self::once())
            ->method('put')
            ->with(
                $idToken,
                $refreshToken,
            );
    }

    /** @test */
    public function authenticate_with_redirect(): void
    {
        $this->authenticateWithNewToken();

        $this->request
            ->expects(self::once())
            ->method('get')
            ->with('code')
            ->willReturn(
                \substr(
                    \str_shuffle(
                        \str_repeat(
                            $x = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ',
                            (int) \ceil(901 / \strlen($x)),
                        ),
                    ),
                    1,
                    801,
                ),
            );

        $this->request
            ->expects(self::exactly(3))
            ->method('getPathInfo')
            ->willReturn('/foobar');

        $this->responseFactory
            ->expects(self::once())
            ->method('redirectTo')
            ->with('/foobar');

        Event::fake();

        $openIDConnectAuthenticated = $this->createOpenIDConnectAuthenticated();
        $this->handle($openIDConnectAuthenticated, false);

        Event::assertDispatched(UserAuthorizedEvent::class);
    }

    /** @test */
    public function authenticate(): void
    {
        $this->authenticateWithNewToken();

        Event::fake();

        $openIDConnectAuthenticated = $this->createOpenIDConnectAuthenticated();
        $return = $this->handle($openIDConnectAuthenticated);

        Event::assertDispatched(UserAuthorizedEvent::class);

        self::assertEquals('arbitrary_value', $return);
    }

    private function createOpenIDConnectAuthenticated(): OpenIDConnectAuthenticated
    {
        return new OpenIDConnectAuthenticated(
            responseFactory: $this->responseFactory,
            openIDConnectClientBuilder: $this->openIDConnectClientBuilder,
            jwtVerifierBuilder: $this->jwtVerifierBuilder,
            tokenStorageAdaptor: $this->storageAdaptor,
            configRepository: $this->configRepository,
        );
    }

    private function handle(
        OpenIDConnectAuthenticated $openIDConnectAuthenticated,
        bool $withReturn = true,
    ): mixed {
        if ($withReturn) {
            $this->closure
                ->expects(self::once())
                ->method('__invoke')
                ->with($this->request)
                ->willReturn('arbitrary_value');
        }

        return $openIDConnectAuthenticated->handle(
            request: $this->request,
            next: \Closure::fromCallable($this->closure),
        );
    }
}
