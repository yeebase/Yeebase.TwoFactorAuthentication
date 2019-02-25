<?php
declare(strict_types=1);
namespace Yeebase\TwoFactorAuthentication\Security\Authentication\Token;

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Mvc\ActionRequest;
use Neos\Flow\Security\Authentication\Token\AbstractToken;
use Neos\Utility\ObjectAccess;
use Yeebase\TwoFactorAuthentication\Domain\ValueObjects\OneTimePassword;

/**
 * An authentication token used to bear 2FA One Time Passwords (OTP)
 */
class OtpToken extends AbstractToken
{
    /**
     * @Flow\Transient
     */
    private const CREDENTIALS_OTP = 'otp';

    /**
     * @Flow\Transient
     * @var array
     */
    protected $credentials = [
        self::CREDENTIALS_OTP => null
    ];

    public function updateCredentials(ActionRequest $actionRequest): void
    {
        if (!$this->isAuthenticated()) {
            /** @noinspection PhpUnhandledExceptionInspection */
            $this->setAuthenticationStatus(self::AUTHENTICATION_NEEDED);
        }
        $httpRequest = $actionRequest->getHttpRequest();
        if ($httpRequest->getMethod() !== 'POST') {
            return;
        }
        $otp = ObjectAccess::getPropertyPath($actionRequest->getInternalArguments(), '__authentication.Yeebase.TwoFactorAuthentication.Security.Authentication.Token.OtpToken.otp');
        if (empty($otp)) {
            return;
        }
        try {
            $this->credentials[self::CREDENTIALS_OTP] = OneTimePassword::fromString($otp);
        } catch (\InvalidArgumentException $exception) {
            /** @noinspection PhpUnhandledExceptionInspection */
            $this->setAuthenticationStatus(self::WRONG_CREDENTIALS);
        }
    }

    public function hasOtp(): bool
    {
        return $this->credentials[self::CREDENTIALS_OTP] !== null;
    }

    public function getOtp(): OneTimePassword
    {
        return $this->credentials[self::CREDENTIALS_OTP];
    }
}
