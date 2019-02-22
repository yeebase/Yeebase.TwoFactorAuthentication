<?php
declare(strict_types=1);
namespace Yeebase\TwoFactorAuthentication\Security\RequestPattern;

use Neos\Flow\Mvc\ActionRequest;
use Neos\Flow\Mvc\RequestInterface;
use Neos\Flow\Security\RequestPatternInterface;
use Neos\Flow\Annotations as Flow;

/**
 * An Authentication Request Pattern that matches all requests that are *not* within the configured routes.setup route
 */
final class ExcludeTwoFactorAuthenticationSetup implements RequestPatternInterface
{

    /**
     * @Flow\InjectConfiguration(path="routes.setup")
     * @var array
     */
    protected $setupRoute;

    public function matchRequest(RequestInterface $request): bool
    {
        if (!$request instanceof ActionRequest) {
            return true;
        }
        if (!isset($this->setupRoute['@package'], $this->setupRoute['@controller'])) {
            return true;
        }
        if ($request->getControllerPackageKey() !== $this->setupRoute['@package']) {
            return true;
        }
        if (isset($this->setupRoute['@subpackage']) && $request->getControllerSubpackageKey() !== $this->setupRoute['@subpackage']) {
            return true;
        }
        if ($request->getControllerName() !== $this->setupRoute['@controller']) {
            return true;
        }
        return false;
    }
}
