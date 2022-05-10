<?php

declare(strict_types=1);

namespace Coddin\OpenIDConnectClient\Http\Middleware;

use Coddin\OpenIDConnectClient\Builder\JWTVerifierBuilder;
use Coddin\OpenIDConnectClient\Storage\TokenStorageAdaptor;
use Illuminate\Http\Request;
use Illuminate\Routing\ResponseFactory;
use Illuminate\Support\Facades\Log;
use Lcobucci\JWT\Encoding\CannotDecodeContent;
use Lcobucci\JWT\Token\InvalidTokenStructure;
use Lcobucci\JWT\Token\UnsupportedHeaderFound;
use Symfony\Component\HttpFoundation\Response;

final class TokenAuthenticated
{
    public function __construct(
        private readonly ResponseFactory $responseFactory,
        private readonly TokenStorageAdaptor $storageAdaptor,
        private readonly JWTVerifierBuilder $jwtVerifierBuilder,
    ) {
    }

    public function handle(Request $request, \Closure $next): mixed
    {
        $bearerToken = $request->bearerToken();

        if ($bearerToken === null) {
            return $this->responseFactory->make(null, Response::HTTP_UNAUTHORIZED);
        }

        $jwtVerifier = $this->jwtVerifierBuilder->execute();
        try {
            $token = $jwtVerifier->parser()->parse($bearerToken);
        } catch (CannotDecodeContent | InvalidTokenStructure | UnsupportedHeaderFound $e) {
            Log::error('Verifying the Bearer Token failed', $e->getTrace());

            return $this->responseFactory->make(null, Response::HTTP_UNAUTHORIZED);
        }

        $this->storageAdaptor->put($token);

        return $next($request);
    }
}
