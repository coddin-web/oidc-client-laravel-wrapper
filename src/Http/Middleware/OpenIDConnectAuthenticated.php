<?php

declare(strict_types=1);

namespace Coddin\OpenIDConnectClient\Http\Middleware;

use Coddin\OpenIDConnectClient\Builder\JWTVerifierBuilder;
use Coddin\OpenIDConnectClient\Builder\OpenIDConnectClientBuilder;
use Coddin\OpenIDConnectClient\Storage\Exception\MissingTokenException;
use Coddin\OpenIDConnectClient\Storage\TokenStorageAdaptor;
use Illuminate\Http\Request;
use Illuminate\Routing\ResponseFactory;
use Illuminate\Support\Facades\Log;
use Jumbojett\OpenIDConnectClientException;
use Symfony\Component\HttpFoundation\Response;

final class OpenIDConnectAuthenticated
{
    public function __construct(
        private readonly ResponseFactory $responseFactory,
        private readonly OpenIDConnectClientBuilder $openIDConnectClientBuilder,
        private readonly JWTVerifierBuilder $jwtVerifierBuilder,
        private readonly TokenStorageAdaptor $storageAdaptor,
    ) {
    }

    public function handle(Request $request, \Closure $next): mixed
    {
        try {
            $token = $this->storageAdaptor->get();
            if ($token->isExpired(new \DateTimeImmutable()) === false) {
                return $next($request);
            }
        } catch (MissingTokenException $e) {
            // Normal behaviour on first time entering the application.
        }

        try {
            $jwtVerifier = $this->jwtVerifierBuilder->execute();
            $openIDClient = $this->openIDConnectClientBuilder->execute();
            $openIDClient->authenticate();

            $this->storageAdaptor->put($jwtVerifier->parser()->parse($openIDClient->getIdToken()));
        } catch (OpenIDConnectClientException $e) {
            Log::error('Authenticating the OpenIDConnect Client failed:');
            Log::error($e->getMessage(), $e->getTrace());

            return $this->responseFactory->make(null, Response::HTTP_UNAUTHORIZED);
        }

        return $next($request);
    }
}
