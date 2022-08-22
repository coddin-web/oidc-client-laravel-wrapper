<?php

/** @noinspection PhpMissingFieldTypeInspection */

declare(strict_types=1);

namespace Coddin\Tests\Unit\Http\Middleware;

use Coddin\OpenIDConnectClient\Builder\JWTVerifierBuilder;
use Coddin\OpenIDConnectClient\Helper\ConfigRepositoryException;
use Coddin\OpenIDConnectClient\Http\Middleware\TokenAuthenticated;
use Coddin\OpenIDConnectClient\Service\Token\Storage\TokenStorageAdaptor;
use Coddin\Tests\Helper\ClosureTestClass;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Validation\ConstraintViolation;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use Lcobucci\JWT\Validator;
use PHPUnit\Framework\MockObject\MockObject;
use Symfony\Component\HttpKernel\Exception\HttpException;

// phpcs:disable PSR1.Methods.CamelCapsMethodName
final class TokenAuthenticatedTest extends \Orchestra\Testbench\TestCase
{
    /** @var TokenStorageAdaptor & MockObject */
    private $storageAdaptor;
    /** @var JWTVerifierBuilder & MockObject */
    private $jwtVerifierBuilder;

    /** @var Request & MockObject */
    private $request;
    /** @var ClosureTestClass & MockObject */
    private $closure;

    protected function setUp(): void
    {
        parent::setUp();

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

        self::expectException(HttpException::class);

        $tokenAuthenticated = $this->createTokenAuthenticated();
        $this->handle($tokenAuthenticated, false);
    }

    /** @test */
    public function bearerToken_config_failed(): void
    {
        $this->request
            ->expects(self::once())
            ->method('bearerToken')
            ->willReturn('bearertoken');

        $this->jwtVerifierBuilder
            ->expects(self::once())
            ->method('execute')
            ->willThrowException(new ConfigRepositoryException());

        self::expectException(HttpException::class);

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

        /** @var Parser & MockObject $parser */
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

        self::expectException(HttpException::class);

        $tokenAuthenticated = $this->createTokenAuthenticated();
        $this->handle($tokenAuthenticated, false);
    }

    /** @test */
    public function verify_token_constraint_violated(): void
    {
        $this->request
            ->expects(self::once())
            ->method('bearerToken')
            ->willReturn('bearertoken');

        $jwtVerifier = $this->createPartialMock(Configuration::class, ['parser', 'validator']);
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

        $token = $this->createPartialMock(Token::class, []);
        $parser
            ->expects(self::once())
            ->method('parse')
            ->with('bearertoken')
            ->willReturn($token);

        $validator = $this->createPartialMock(Validator::class, ['assert', 'validate']);
        $jwtVerifier
            ->expects(self::once())
            ->method('validator')
            ->willReturn($validator);

        $validator
            ->expects(self::once())
            ->method('assert')
            ->willThrowException(RequiredConstraintsViolated::fromViolations(new ConstraintViolation('Violation')));

        Log::shouldReceive('error')
            ->withSomeOfArgs('Validating the Bearer Token failed: Violation');

        self::expectException(HttpException::class);

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

        $jwtVerifier = $this->createPartialMock(Configuration::class, ['parser', 'validator']);
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

        $token = $this->createPartialMock(Token::class, []);
        $parser
            ->expects(self::once())
            ->method('parse')
            ->with('bearertoken')
            ->willReturn($token);

        $validator = $this->createPartialMock(Validator::class, ['assert', 'validate']);
        $jwtVerifier
            ->expects(self::once())
            ->method('validator')
            ->willReturn($validator);

        $validator
            ->expects(self::once())
            ->method('assert');

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
