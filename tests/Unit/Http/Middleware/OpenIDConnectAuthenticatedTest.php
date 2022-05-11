<?php

declare(strict_types=1);

namespace Coddin\Tests\Unit\Http\Middleware;

use Coddin\OpenIDConnectClient\Builder\JWTVerifierBuilder;
use Coddin\OpenIDConnectClient\Builder\OpenIDConnectClientBuilder;
use Coddin\OpenIDConnectClient\Http\Middleware\OpenIDConnectAuthenticated;
use Coddin\OpenIDConnectClient\Storage\Exception\MissingTokenException;
use Coddin\OpenIDConnectClient\Storage\TokenStorageAdaptor;
use Coddin\Tests\Helper\ClosureTestClass;
use Illuminate\Http\Request;
use Illuminate\Routing\ResponseFactory;
use Illuminate\Support\Facades\Log;
use Jumbojett\OpenIDConnectClient;
use Jumbojett\OpenIDConnectClientException;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Token;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

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

    /** @var Request & MockObject */
    private Request|MockObject $request;
    /** @var ClosureTestClass & MockObject */
    private ClosureTestClass|MockObject $closure;

    protected function setUp(): void
    {
        $this->responseFactory = $this->createMock(ResponseFactory::class);
        $this->openIDConnectClientBuilder = $this->createPartialMock(OpenIDConnectClientBuilder::class, ['execute']);
        $this->jwtVerifierBuilder = $this->createPartialMock(JWTVerifierBuilder::class, ['execute']);
        $this->storageAdaptor = $this->createMock(TokenStorageAdaptor::class);

        $this->request = $this->createMock(Request::class);
        $this->closure = $this->createMock(ClosureTestClass::class);
    }

    /** @test */
    public function token_expired(): void
    {
        $token = $this->createMock(Token::class);
        $token
            ->expects(self::once())
            ->method('isExpired')
            ->willReturn(false);

        $this->storageAdaptor
            ->expects(self::once())
            ->method('get')
            ->willReturn($token);

        $openIDConnectAuthenticated = $this->createOpenIDConnectAuthenticated();
        $return = $this->handle($openIDConnectAuthenticated);

        self::assertEquals('arbitrary_value', $return);
    }

    /** @test */
    public function open_ID_client_exception(): void
    {
        $this->storageAdaptor
            ->expects(self::once())
            ->method('get')
            ->willThrowException(new MissingTokenException());

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

        $this->responseFactory
            ->expects(self::once())
            ->method('make')
            ->with(null, 401);

        $openIDConnectAuthenticated = $this->createOpenIDConnectAuthenticated();
        $this->handle($openIDConnectAuthenticated, false);
    }

    /** @test */
    public function authenticate(): void
    {
        $this->storageAdaptor
            ->expects(self::once())
            ->method('get')
            ->willThrowException(new MissingTokenException());

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

        $parser = $this->createPartialMock(Token\Parser::class, ['parse']);
        $jwtVerifier
            ->expects(self::once())
            ->method('parser')
            ->willReturn($parser);

        $openIDClient
            ->expects(self::once())
            ->method('getIdToken')
            ->willReturn('id_token.second_part.third_part');

        $token = $this->createMock(Token::class);
        $parser
            ->expects(self::once())
            ->method('parse')
            ->with('id_token.second_part.third_part')
            ->willReturn($token);

        $this->storageAdaptor
            ->expects(self::once())
            ->method('put')
            ->with($token);

        $openIDConnectAuthenticated = $this->createOpenIDConnectAuthenticated();
        $return = $this->handle($openIDConnectAuthenticated);

        self::assertEquals('arbitrary_value', $return);
    }

    private function createOpenIDConnectAuthenticated(): OpenIDConnectAuthenticated
    {
        return new OpenIDConnectAuthenticated(
            responseFactory: $this->responseFactory,
            openIDConnectClientBuilder: $this->openIDConnectClientBuilder,
            jwtVerifierBuilder: $this->jwtVerifierBuilder,
            storageAdaptor: $this->storageAdaptor,
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
