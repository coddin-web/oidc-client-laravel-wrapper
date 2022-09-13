<?php

declare(strict_types=1);

namespace Coddin\OpenIDConnectClient\Http\Middleware;

use Coddin\OpenIDConnectClient\Builder\JWTVerifierBuilder;
use Coddin\OpenIDConnectClient\Helper\ConfigRepositoryException;
use Coddin\OpenIDConnectClient\Service\Token\Storage\TokenStorageAdaptor;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Session;
use Lcobucci\JWT\Encoding\CannotDecodeContent;
use Lcobucci\JWT\Token\InvalidTokenStructure;
use Lcobucci\JWT\Token\UnsupportedHeaderFound;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\HttpException;

final class TokenAuthenticated
{
    public function __construct(
        private readonly TokenStorageAdaptor $storageAdaptor,
        private readonly JWTVerifierBuilder $jwtVerifierBuilder,
    ) {
    }

    /**
     * @throws HttpException
     */
    public function handle(Request $request, \Closure $next): mixed
    {
        $bearerToken = $request->bearerToken();

        if ($bearerToken === null) {
            throw new HttpException(Response::HTTP_UNAUTHORIZED);
        }

        try {
            $jwtVerifier = $this->jwtVerifierBuilder->execute();
        } catch (ConfigRepositoryException $e) {
            throw new HttpException(Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        try {
            $token = $jwtVerifier->parser()->parse($bearerToken);
        } catch (CannotDecodeContent | InvalidTokenStructure | UnsupportedHeaderFound $e) {
            Log::error('Verifying the Bearer Token failed', $e->getTrace());

            throw new HttpException(Response::HTTP_UNAUTHORIZED);
        }

        $constraints = $jwtVerifier->validationConstraints();
        try {
            $jwtVerifier->validator()->assert($token, ...$constraints);
        } catch (RequiredConstraintsViolated $e) {
            foreach ($e->violations() as $violation) {
                Log::error(
                    sprintf(
                        'Validating the Bearer Token failed: %s',
                        $violation->getMessage(),
                    ),
                    $violation->getTrace(),
                );
            }

            throw new HttpException(Response::HTTP_UNAUTHORIZED);
        }

        Session::put(TokenStorageAdaptor::ID_TOKEN_STORAGE_KEY, $token);

        return $next($request);
    }
}
