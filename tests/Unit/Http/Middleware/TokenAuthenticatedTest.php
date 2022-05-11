<?php

declare(strict_types=1);

namespace Coddin\Tests\Unit\Http\Middleware;

use Coddin\OpenIDConnectClient\Builder\JWTVerifierBuilder;
use Coddin\OpenIDConnectClient\Http\Middleware\TokenAuthenticated;
use Coddin\OpenIDConnectClient\Storage\TokenStorageAdaptor;
use Coddin\Tests\Helper\ClosureTestClass;
use Illuminate\Http\Request;
use Illuminate\Routing\ResponseFactory;
use Illuminate\Support\Facades\Log;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\Parser;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

// phpcs:disable PSR1.Methods.CamelCapsMethodName
final class TokenAuthenticatedTest extends TestCase
{
    /** @var ResponseFactory & MockObject */
    private ResponseFactory|MockObject $responseFactory;
    /** @var TokenStorageAdaptor & MockObject */
    private TokenStorageAdaptor|MockObject $storageAdaptor;
    /** @var JWTVerifierBuilder & MockObject */
    private JWTVerifierBuilder|MockObject $jwtVerifierBuilder;

    /** @var Request & MockObject */
    private Request|MockObject $request;
    /** @var ClosureTestClass & MockObject */
    private ClosureTestClass|MockObject $closure;

    protected function setUp(): void
    {
        $this->responseFactory = $this->createMock(ResponseFactory::class);
        $this->storageAdaptor = $this->createMock(TokenStorageAdaptor::class);
        $this->jwtVerifierBuilder = $this->createPartialMock(JWTVerifierBuilder::class, ['execute']);

        $this->request = $this->createMock(Request::class);
        $this->closure = $this->createMock(ClosureTestClass::class);
    }

    /** @test */
    public function missing_bearerToken(): void
    {
        $this->request
            ->expects(self::once())
            ->method('bearerToken')
            ->willReturn(null);

        $this->responseFactory
            ->expects(self::once())
            ->method('make')
            ->with(null, 401);

        $tokenAuthenticated = $this->createTokenAuthenticated();
        $this->handle($tokenAuthenticated, false);
    }

    /** @test */
    public function bearerToken_verification_failed(): void
    {
        $this->request
            ->expects(self::once())
            ->method('bearerToken')
            ->willReturn('bearertoken');

        $jwtVerifier = $this->createPartialMock(Configuration::class, ['parser']);
        $this->jwtVerifierBuilder
            ->expects(self::once())
            ->method('execute')
            ->willReturn($jwtVerifier);

        $parser = $this->createPartialMock(Parser::class, ['parse']);
        $jwtVerifier
            ->expects(self::once())
            ->method('parser')
            ->willReturn($parser);

        $parser
            ->expects(self::once())
            ->method('parse')
            ->with('bearertoken')
            ->willThrowException(new Token\InvalidTokenStructure());

        Log::shouldReceive('error')
            ->once()
            ->withSomeOfArgs('Verifying the Bearer Token failed');

        $this->responseFactory
            ->expects(self::once())
            ->method('make')
            ->with(null, 401);

        $tokenAuthenticated = $this->createTokenAuthenticated();
        $this->handle($tokenAuthenticated, false);
    }

    /** @test */
    public function verify_token(): void
    {
        $this->request
            ->expects(self::once())
            ->method('bearerToken')
            ->willReturn('bearertoken');

        $jwtVerifier = $this->createPartialMock(Configuration::class, ['parser']);
        $this->jwtVerifierBuilder
            ->expects(self::once())
            ->method('execute')
            ->willReturn($jwtVerifier);

        $parser = $this->createPartialMock(Parser::class, ['parse']);
        $jwtVerifier
            ->expects(self::once())
            ->method('parser')
            ->willReturn($parser);

        $token = $this->createMock(Token::class);
        $parser
            ->expects(self::once())
            ->method('parse')
            ->with('bearertoken')
            ->willReturn($token);

        $this->storageAdaptor
            ->expects(self::once())
            ->method('put')
            ->with($token);

        $tokenAuthenticated = $this->createTokenAuthenticated();
        $return = $this->handle($tokenAuthenticated);

        self::assertEquals('arbitrary_value', $return);
    }

    private function createTokenAuthenticated(): TokenAuthenticated
    {
        return new TokenAuthenticated(
            responseFactory: $this->responseFactory,
            storageAdaptor: $this->storageAdaptor,
            jwtVerifierBuilder: $this->jwtVerifierBuilder,
        );
    }

    private function handle(
        TokenAuthenticated $tokenAuthenticated,
        bool $withReturn = true,
    ): mixed {
        if ($withReturn) {
            $this->closure
                ->expects(self::once())
                ->method('__invoke')
                ->with($this->request)
                ->willReturn('arbitrary_value');
        }

        return $tokenAuthenticated->handle(
            request: $this->request,
            next: \Closure::fromCallable($this->closure),
        );
    }
}
