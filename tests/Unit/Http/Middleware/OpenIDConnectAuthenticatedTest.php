<?php

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
    private ResponseFactory|MockObject $responseFactory;
    /** @var OpenIDConnectClientBuilder & MockObject */
    private OpenIDConnectClientBuilder|MockObject $openIDConnectClientBuilder;
    /** @var JWTVerifierBuilder & MockObject */
    private JWTVerifierBuilder|MockObject $jwtVerifierBuilder;
    /** @var TokenStorageAdaptor & MockObject */
    private TokenStorageAdaptor|MockObject $storageAdaptor;
    /** @var ConfigRepository & MockObject */
    private ConfigRepository|MockObject $configRepository;

    /** @var Request & MockObject */
    private Request|MockObject $request;
    /** @var ClosureTestClass & MockObject */
    private ClosureTestClass|MockObject $closure;

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
    public function existing_token_expired(): void
    {
        $token = $this->createMock(Token::class);
        $token
            ->expects(self::once())
            ->method('isExpired')
            ->willReturn(true);

        $this->storageAdaptor
            ->expects(self::once())
            ->method('find')
            ->willReturn($token);

        $this->storageAdaptor
            ->expects(self::once())
            ->method('forget');

        $this->responseFactory
            ->expects(self::once())
            ->method('redirectTo')
            ->with('/foobar');

        $this->request
            ->expects(self::once())
            ->method('getPathInfo')
            ->willReturn('/foobar');

        $openIDConnectAuthenticated = $this->createOpenIDConnectAuthenticated();
        $this->handle($openIDConnectAuthenticated, false);
    }

    /**
     * @test
     * @dataProvider existingTokenIntrospectData
     * @param class-string<\Throwable> $exceptionThrow
     */
    public function existing_token_introspect_fail(
        \Exception $exceptionCatch,
        string $exceptionThrow,
    ): void {
        $token = $this->createMock(Token::class);
        $token
            ->expects(self::once())
            ->method('isExpired')
            ->willReturn(false);

        $this->storageAdaptor
            ->expects(self::once())
            ->method('find')
            ->willReturn($token);

        $openIDClient = $this->createMock(OpenIDConnectClient::class);
        $openIDClient
            ->expects(self::once())
            ->method('introspectToken')
            ->willThrowException($exceptionCatch);

        $this->openIDConnectClientBuilder
            ->expects(self::once())
            ->method('execute')
            ->willReturn($openIDClient);

        self::expectException($exceptionThrow);

        $openIDConnectAuthenticated = $this->createOpenIDConnectAuthenticated();
        $this->handle($openIDConnectAuthenticated, false);
    }

    /**
     * @return array<int, array{ConfigRepositoryException|OpenIDConnectClientException, string}>
     */
    private function existingTokenIntrospectData(): array
    {
        return [
            [
                new ConfigRepositoryException(''),
                HttpException::class,
            ],
            [
                new OpenIDConnectClientException(''),
                HttpException::class,
            ],
        ];
    }

    /** @test */
    public function existing_token_introspect_failed_response(): void
    {
        $token = $this->createMock(Token::class);
        $token
            ->expects(self::once())
            ->method('isExpired')
            ->willReturn(false);

        $this->storageAdaptor
            ->expects(self::once())
            ->method('find')
            ->willReturn($token);

        $openIDClient = $this->createMock(OpenIDConnectClient::class);
        $openIDClient
            ->expects(self::once())
            ->method('introspectToken')
            ->willReturn([]);

        $this->storageAdaptor
            ->expects(self::once())
            ->method('forget');

        $this->openIDConnectClientBuilder
            ->expects(self::once())
            ->method('execute')
            ->willReturn($openIDClient);

        $this->responseFactory
            ->expects(self::once())
            ->method('redirectTo')
            ->with('/foobar');

        $this->request
            ->expects(self::once())
            ->method('getPathInfo')
            ->willReturn('/foobar');

        $openIDConnectAuthenticated = $this->createOpenIDConnectAuthenticated();
        $this->handle($openIDConnectAuthenticated, false);
    }

    /** @test */
    public function existing_token_introspect_active_token(): void
    {
        $token = $this->createMock(Token::class);
        $token
            ->expects(self::once())
            ->method('isExpired')
            ->willReturn(false);

        $this->storageAdaptor
            ->expects(self::once())
            ->method('find')
            ->willReturn($token);

        $activeResponse = new \stdClass();
        $activeResponse->active = true;

        $openIDClient = $this->createMock(OpenIDConnectClient::class);
        $openIDClient
            ->expects(self::once())
            ->method('introspectToken')
            ->willReturn($activeResponse);

        $this->openIDConnectClientBuilder
            ->expects(self::once())
            ->method('execute')
            ->willReturn($openIDClient);

        $openIDConnectAuthenticated = $this->createOpenIDConnectAuthenticated();
        $return = $this->handle($openIDConnectAuthenticated);

        self::assertEquals('arbitrary_value', $return);
    }

    /** @test */
    public function existing_token_introspect_inactive_token(): void
    {
        $token = $this->createMock(Token::class);
        $token
            ->expects(self::once())
            ->method('isExpired')
            ->willReturn(false);

        $this->storageAdaptor
            ->expects(self::once())
            ->method('find')
            ->willReturn($token);

        $activeResponse = new \stdClass();
        $activeResponse->active = false;

        $openIDClient = $this->createMock(OpenIDConnectClient::class);
        $openIDClient
            ->expects(self::once())
            ->method('introspectToken')
            ->willReturn($activeResponse);

        $this->openIDConnectClientBuilder
            ->expects(self::once())
            ->method('execute')
            ->willReturn($openIDClient);

        $this->storageAdaptor
            ->expects(self::once())
            ->method('forget');

        $this->responseFactory
            ->expects(self::once())
            ->method('redirectTo')
            ->with('/foobar');

        $this->request
            ->expects(self::once())
            ->method('getPathInfo')
            ->willReturn('/foobar');

        $openIDConnectAuthenticated = $this->createOpenIDConnectAuthenticated();
        $this->handle($openIDConnectAuthenticated, false);
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

        $token = $this->createPartialMock(Token\Plain::class, ['claims']);
        $token
            ->expects(self::exactly(3))
            ->method('claims')
            ->willReturn($dataSet);

        $parser
            ->expects(self::once())
            ->method('parse')
            ->with('id_token.second_part.third_part')
            ->willReturn($token);

        $this->storageAdaptor
            ->expects(self::once())
            ->method('put')
            ->with($token);
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
                    901,
                ),
            );

        $this->request
            ->expects(self::once())
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
