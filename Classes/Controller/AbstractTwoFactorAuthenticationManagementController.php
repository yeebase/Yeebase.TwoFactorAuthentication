<?php
namespace Yeebase\TwoFactorAuthentication\Controller;

use Neos\Flow\Annotations as Flow;
use Neos\Error\Messages\Message;
use Neos\Flow\Mvc\Controller\ActionController;
use Neos\Flow\Security\Context;
use Yeebase\TwoFactorAuthentication\Service\TwoFactorAuthenticationService;

abstract class AbstractTwoFactorAuthenticationManagementController extends ActionController
{

    /**
     * @var Context
     * @Flow\Inject
     */
    protected $securityContext;

    /**
     * @var TwoFactorAuthenticationService
     * @Flow\Inject
     */
    protected $twoFactorAuthenticationService;

    public function configureAction()
    {
        $account = $this->securityContext->getAccount();
        $enabled = $this->twoFactorAuthenticationService->hasTwoFactorAuthenticationEnabled($account);

        if (! $enabled) {
            $activationQrCode = $this->twoFactorAuthenticationService->createActivationQrCode($account);
            $this->view->assign('activationQrCode', $activationQrCode);
        }
    }

    public function enableAction(string $secret)
    {
        $account = $this->securityContext->getAccount();

        if ($this->twoFactorAuthenticationService->validateSecret($secret, $account, true)) {
            $this->twoFactorAuthenticationService->enableTwoFactorAuthentication($account);
            $this->addFlashMessage('Two-Factor-Authentication activated.', '', Message::SEVERITY_OK, [], 1511944292);
        } else {
            $this->addFlashMessage('Wrong Secret.', '', Message::SEVERITY_ERROR, [], 1511944293);
        }

        $this->redirect('configure');
    }

    public function disableAction(string $secret)
    {
        $account = $this->securityContext->getAccount();

        if ($this->twoFactorAuthenticationService->validateSecret($secret, $account)) {
            $this->twoFactorAuthenticationService->disableTwoFactorAuthentication($account);
            $this->addFlashMessage('Two-Factor-Authentication deactivated.', '', Message::SEVERITY_OK, [], 1511944294);
        } else {
            $this->addFlashMessage('Wrong Secret.', '', Message::SEVERITY_ERROR, [], 1511944293);
        }

        $this->redirect('configure');
    }
}
