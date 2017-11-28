<?php
namespace Yeebase\TwoFactorAuthentication\Security\Authentication\Token;

use Neos\Flow\Mvc\ActionRequest;
use Neos\Flow\Security\Authentication\Token\AbstractToken;
use Neos\Utility\ObjectAccess;

/**
 * An authentication token used for two-factor-authentication with username and password as well as a secret.
 */
class TwoFactorUsernamePasswordToken extends AbstractToken
{
    const CREDENTIALS_USERNAME = 'username';
    const CREDENTIALS_PASSWORD = 'password';
    const CREDENTIALS_TWO_FACTOR_SECRET = 'twoFactorSecret';

    protected $credentials = [
        self::CREDENTIALS_USERNAME => '',
        self::CREDENTIALS_PASSWORD => '',
        self::CREDENTIALS_TWO_FACTOR_SECRET => ''
    ];

    /**
     * In a first request you need to send the username and password in these two POST parameters:
     *       __authentication[Yeebase][TwoFactorAuthentication][Security][Authentication][Token][TwoFactorUsernamePasswordToken][username]
     *   and __authentication[Yeebase][TwoFactorAuthentication][Security][Authentication][Token][TwoFactorUsernamePasswordToken][password]
     *
     * In a second request you need to send the respective Two-Factor-Authentication token in this POST parameter:
     *       __authentication[Yeebase][TwoFactorAuthentication][Security][Authentication][Token][TwoFactorUsernamePasswordToken][twoFactorSecret]
     *
     * @param ActionRequest $actionRequest The current action request
     * @return void
     */
    public function updateCredentials(ActionRequest $actionRequest): void
    {
        $httpRequest = $actionRequest->getHttpRequest();
        if ($httpRequest->getMethod() !== 'POST') {
            return;
        }

        $arguments = $actionRequest->getInternalArguments();
        $username = ObjectAccess::getPropertyPath($arguments, '__authentication.Yeebase.TwoFactorAuthentication.Security.Authentication.Token.TwoFactorUsernamePasswordToken.' . self::CREDENTIALS_USERNAME);
        $password = ObjectAccess::getPropertyPath($arguments, '__authentication.Yeebase.TwoFactorAuthentication.Security.Authentication.Token.TwoFactorUsernamePasswordToken.' . self::CREDENTIALS_PASSWORD);
        $twoFactorSecret = ObjectAccess::getPropertyPath($arguments, '__authentication.Yeebase.TwoFactorAuthentication.Security.Authentication.Token.TwoFactorUsernamePasswordToken.' . self::CREDENTIALS_TWO_FACTOR_SECRET);

        if (!empty($username) && !empty($password)) {
            $this->credentials[self::CREDENTIALS_USERNAME] = $username;
            $this->credentials[self::CREDENTIALS_PASSWORD] = $password;
            $this->credentials[self::CREDENTIALS_TWO_FACTOR_SECRET] = '';
            $this->setAuthenticationStatus(self::AUTHENTICATION_NEEDED);
        }

        if (!empty($twoFactorSecret)) {
            $this->credentials[self::CREDENTIALS_TWO_FACTOR_SECRET] = $twoFactorSecret;
            $this->setAuthenticationStatus(self::AUTHENTICATION_NEEDED);
        }
    }
}
