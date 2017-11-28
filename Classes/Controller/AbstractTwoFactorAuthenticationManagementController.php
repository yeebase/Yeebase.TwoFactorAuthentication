<?php
namespace Yeebase\TwoFactorAuthentication\Controller;

use Neos\Flow\Annotations as Flow;
use Neos\Error\Messages\Message;
use Neos\Flow\Mvc\Controller\ActionController;
use Yeebase\TwoFactorAuthentication\Service\TwoFactorAuthenticationService;

abstract class AbstractTwoFactorAuthenticationManagementController extends ActionController
{

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
            $this->addFlashMessage('Zwei-Faktor-Authentisierung aktiviert.');
        } else {
            $this->addFlashMessage('Falsches Secret.', Message::SEVERITY_ERROR);
        }

        $this->redirect('configure');
    }

    public function disableAction(string $secret)
    {
        $account = $this->securityContext->getAccount();

        if ($this->twoFactorAuthenticationService->validateSecret($secret, $account)) {
            $this->twoFactorAuthenticationService->disableTwoFactorAuthentication($account);
            $this->addFlashMessage('Zwei-Faktor-Authentisierung deaktiviert.');
        } else {
            $this->addFlashMessage('Falsches Secret.', Message::SEVERITY_ERROR);
        }

        $this->redirect('configure');
    }
}
