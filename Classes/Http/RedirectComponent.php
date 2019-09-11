<?php
declare(strict_types=1);
namespace Yeebase\TwoFactorAuthentication\Http;

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Http\Component\ComponentChain;
use Neos\Flow\Http\Component\ComponentContext;
use Neos\Flow\Http\Component\ComponentInterface;
use Neos\Flow\Http\Request as HttpRequest;
use Neos\Flow\Mvc\ActionRequest;
use Neos\Flow\Mvc\Routing\UriBuilder;

/**
 * A HTTP component that redirects to the configured 2FA login/setup routes if requested
 */
final class RedirectComponent implements ComponentInterface
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

    public function handle(ComponentContext $componentContext)
    {
        $redirectTarget = $componentContext->getParameter(static::class, 'redirect');
        if ($redirectTarget === null) {
            return;
        }
        if ($redirectTarget === self::REDIRECT_LOGIN) {
            $this->redirectToLogin($componentContext);
        } elseif ($redirectTarget === self::REDIRECT_SETUP) {
            $this->redirectToSetup($componentContext);
        } else {
            throw new \RuntimeException(sprintf('Invalid redirect target "%s"', $redirectTarget), 1568189192);
        }
    }

    /**
     * Triggers a redirect to the 2FA login route configured at routes.login or throws an exception if the configuration is missing/incorrect
     */
    private function redirectToLogin(ComponentContext $componentContext): void
    {
        try {
            $this->validateRouteValues($this->loginRouteValues);
        } catch (\InvalidArgumentException $exception) {
            throw new \RuntimeException('Missing/invalid routes.login configuration: ' . $exception->getMessage(), 1550660144, $exception);
        }
        $this->redirect($componentContext, $this->loginRouteValues);
    }

    /**
     * Triggers a redirect to the 2FA setup route configured at routes.setup or throws an exception if the configuration is missing/incorrect
     */
    private function redirectToSetup(ComponentContext $componentContext): void
    {
        try {
            $this->validateRouteValues($this->setupRouteValue);
        } catch (\InvalidArgumentException $exception) {
            throw new \RuntimeException('Missing/invalid routes.setup configuration: ' . $exception->getMessage(), 1550660178, $exception);
        }
        $this->redirect($componentContext, $this->setupRouteValue);
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

    private  function redirect(ComponentContext $componentContext, array $routeValues): void
    {
        /** @var HttpRequest $httpRequest */
        $httpRequest = $componentContext->getHttpRequest();
        $actionRequest = new ActionRequest($httpRequest);
        $uriBuilder = new UriBuilder();
        $uriBuilder->setRequest($actionRequest);
        $redirectUrl = $uriBuilder->setCreateAbsoluteUri(true)->setFormat('html')->build($routeValues);

        $componentContext->replaceHttpResponse($componentContext->getHttpResponse()->withStatus(303)->withHeader('Location', $redirectUrl));
        $componentContext->setParameter(ComponentChain::class, 'cancel', true);
    }
}
