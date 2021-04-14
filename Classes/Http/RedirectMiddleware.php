<?php
declare(strict_types=1);
namespace Yeebase\TwoFactorAuthentication\Http;

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Mvc\ActionRequest;
use Neos\Flow\Mvc\Routing\UriBuilder;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use GuzzleHttp\Psr7\Response;

/**
 * A HTTP component that redirects to the configured 2FA login/setup routes if requested
 */
final class RedirectMiddleware implements MiddlewareInterface
{
    public const REDIRECT_LOGIN = 'login';
    public const REDIRECT_SETUP = 'setup';

    /**
     * @Flow\InjectConfiguration(path="routes.login")
     * @var array
     */
    protected $loginRouteValues;

    /**
     * @Flow\InjectConfiguration(path="routes.setup")
     * @var array
     */
    protected $setupRouteValue;

    public function process(ServerRequestInterface $request, RequestHandlerInterface $next): ResponseInterface
    {
        $response = $next->handle($request);
        // TODO: Find a better solution to communicate from TokenProvider to this middleware
        $redirectTarget = $response->getHeaderLine(static::class . '.redirect');
        if ($redirectTarget === null) {
            return $response;
        }
        if ($redirectTarget === self::REDIRECT_LOGIN) {
            return $this->redirectToLogin($request);
        } elseif ($redirectTarget === self::REDIRECT_SETUP) {
            return $this->redirectToSetup($request);
        } else {
            throw new \RuntimeException(sprintf('Invalid redirect target "%s"', $redirectTarget), 1568189192);
        }
    }

    /**
     * Triggers a redirect to the 2FA login route configured at routes.login or throws an exception if the configuration is missing/incorrect
     */
    private function redirectToLogin(ServerRequestInterface $request): ResponseInterface
    {
        try {
            $this->validateRouteValues($this->loginRouteValues);
        } catch (\InvalidArgumentException $exception) {
            throw new \RuntimeException('Missing/invalid routes.login configuration: ' . $exception->getMessage(), 1550660144, $exception);
        }
        return $this->redirect($request, $this->loginRouteValues);
    }

    /**
     * Triggers a redirect to the 2FA setup route configured at routes.setup or throws an exception if the configuration is missing/incorrect
     */
    private function redirectToSetup(ServerRequestInterface $request): ResponseInterface
    {
        try {
            $this->validateRouteValues($this->setupRouteValue);
        } catch (\InvalidArgumentException $exception) {
            throw new \RuntimeException('Missing/invalid routes.setup configuration: ' . $exception->getMessage(), 1550660178, $exception);
        }
        return $this->redirect($request, $this->setupRouteValue);
    }

    private function validateRouteValues(array $routeValues): void
    {
        $requiredRouteValues = ['@package', '@controller', '@action'];
        foreach ($requiredRouteValues as $routeValue) {
            if (!array_key_exists($routeValue, $routeValues)) {
                throw new \InvalidArgumentException(sprintf('Missing "%s" route value', $routeValue), 1550660039);
            }
        }
    }

    private  function redirect(ServerRequestInterface $httpRequest, array $routeValues): ResponseInterface
    {
        $actionRequest = ActionRequest::fromHttpRequest($httpRequest);
        $uriBuilder = new UriBuilder();
        $uriBuilder->setRequest($actionRequest);
        $redirectUrl = $uriBuilder->setCreateAbsoluteUri(true)->setFormat('html')->build($routeValues);

        return (new Response())->withStatus(303)->withHeader('Location', $redirectUrl);
    }
}
