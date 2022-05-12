<?php

declare(strict_types=1);

namespace Coddin\OpenIDConnectClient\Http\Middleware;

use Coddin\OpenIDConnectClient\Builder\JWTVerifierBuilder;
use Coddin\OpenIDConnectClient\Builder\OpenIDConnectClientBuilder;
use Coddin\OpenIDConnectClient\Helper\ConfigRepository;
use Coddin\OpenIDConnectClient\Helper\ConfigRepositoryException;
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
        private readonly TokenStorageAdaptor $tokenStorageAdaptor,
        private readonly ConfigRepository $configRepository,
    ) {
    }

    /**
     * @throws ConfigRepositoryException
     * @throws OpenIDConnectClientException
     */
    public function handle(Request $request, \Closure $next): mixed
    {
        try {
            $token = $this->tokenStorageAdaptor->get();

            $openIDClient = $this->openIDConnectClientBuilder->execute();
            $stillActiveResponse = $openIDClient->introspectToken(
                token: $token->toString(),
                clientSecret: $this->configRepository->getAsString('oidc.client.secret'),
            );

            if (!is_object($stillActiveResponse)) {
                $this->tokenStorageAdaptor->forget();

                return $this->responseFactory->redirectTo('/');
            }

            // This is a shortcoming of the library returning an unstructured object.
            /* @phpstan-ignore-next-line */
            if ($stillActiveResponse->active === true) {
                return $next($request);
            } else {
                $this->tokenStorageAdaptor->forget();

                return $this->responseFactory->redirectTo('/');
            }
        } catch (MissingTokenException $e) {
            // Normal behaviour on first time entering the application.
        }

        try {
            $jwtVerifier = $this->jwtVerifierBuilder->execute();
            $openIDClient = $this->openIDConnectClientBuilder->execute();
            $openIDClient->authenticate();

            $this->tokenStorageAdaptor->put(
                token: $jwtVerifier->parser()->parse($openIDClient->getIdToken()),
            );
        } catch (OpenIDConnectClientException $e) {
            Log::error('Authenticating the OpenIDConnect Client failed:');
            Log::error($e->getMessage(), $e->getTrace());

            return $this->responseFactory->make(null, Response::HTTP_UNAUTHORIZED);
        }

        $oauthCode = $request->get('code');
        if (is_string($oauthCode) && strlen($oauthCode) > 900) {
            return $this->responseFactory->redirectTo($request->getPathInfo());
        }

        return $next($request);
    }
}
