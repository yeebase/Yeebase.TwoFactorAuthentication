<?php
namespace Yeebase\TwoFactorAuthentication\Controller;

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Security\Authentication\Controller\AbstractAuthenticationController;

abstract class AbstractTwoFactorAuthenticationController extends AbstractAuthenticationController
{

    public function insertSecretAction()
    {
    }
}
