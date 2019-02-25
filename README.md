# Yeebase.TwoFactorAuthentication

The Yeebase.TwoFactorAuthentication Flow package contains extensions to the Flow authentication mechanism
that let you implement Two-Factor-Authentication (2FA) easily.

It provides a new [Authentication Provider](https://flowframework.readthedocs.io/en/stable/TheDefinitiveGuide/PartIII/Security.html#authentication)
that can be used in addition to existing providers in order to enable 2FA via One-time Passwords (OTP).

## Installation

This package can be installed via [composer](https://getcomposer.org):

    composer require yeebase/twofactorauthentication

This package requires a new database table `yeebase_twofactorauthentication_secret` that can be added via:

    ./flow doctrine:migrate

## Configuration

The following part describes the integration of the Two-Factor-Authentication package into an existing Flow Application.
After installation Two-Factor-Authentication is considered to be disabled for all accounts in the system.

### Authentication Provider

This package provides a `TwoFactorAuthenticationProvider` that has to be configured _in addition_ to already existing providers.
Furthermore the _authenticationStrategy_ has to be set to `allTokens` in order to make sure that both providers are taken into account.

#### Example:

`Settings.yaml`:
```yaml
Neos:
  Flow:
    security:
      authentication:
        authenticationStrategy: 'allTokens'
        providers:
          'Some.Package:Default':
            # That assumes that the "PersistedUsernamePasswordProvider" is used as base authentication:
            provider: 'PersistedUsernamePasswordProvider'

          'Some.Package:2FA':
            provider: 'Yeebase\TwoFactorAuthentication\Security\Authentication\Provider\TwoFactorAuthenticationProvider'
```

### Application name and Routes

If a  `TwoFactorAuthenticationProvider` 


`Settings.yaml`:
```yaml
Yeebase:
  TwoFactorAuthentication:
    # This is the "issuer" that will be displayed in the authenticator app like: <issuer> (<holder>)
    applicationName: 'Some Application'
    routes:
      login:
        '@package':    'Some.Package'
        '@controller': 'Login'
        '@action':     'twoFactor'
```

`Login/TwoFacor.html`
```html
...
<f:form action="authenticate">
    <div class="form-group">
        <label for="otp">2FA Code</label>
        <f:form.textfield name="__authentication[Yeebase][TwoFactorAuthentication][Security][Authentication][Token][OtpToken][otp]" id="otp" additionalAttributes="{autofocus: true, autocomplete: 'off'}" />
    </div>
    <f:form.submit value="Enter" />
</f:form>
...
```

Instead of using the default UsernamePasswordProvider, adapt your settings to use the following provider instead: `Yeebase\TwoFactorAuthentication\Security\Authentication\Provider\TwoFactorAuthenticationProvider`

### Force Two-Factor Authentication

By default 2FA can be enabled per account and it is not required if it is not enabled for the account that is authenticated.
In order to _require_ users to log in with Two-Factor Authentication the `Yeebase.TwoFactorAuthentication.requireTwoFactorAuthentication` flag can be set.
With that in place the One-time Password _has to be specified_ whenever an account is authenticated.
To avoid this to leading to an exception when 2FA is not yet enabled for the given account, a _setup_ can be configured that allows the user to initialize the 2FA.



`Settings.yaml`:
```yaml
Yeebase:
  TwoFactorAuthentication:
    requireTwoFactorAuthentication: true
    routes:
      # ...
      setup:
        '@package':    'Some.Package'
        '@controller': 'TwoFactorAuthenticationSetup'
        '@action':     'index'
```

And the corresponding Setup Controller (example):


`TwoFactorAuthenticationSetupController.php`
```php
<?php
declare(strict_types=1);
namespace Some\Package\Controller;

use Neos\Error\Messages\Message;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Mvc\Controller\ActionController;
use Neos\Flow\Security\Account;
use Neos\Flow\Security\Context;
use Neos\Flow\Security\Exception\AccessDeniedException;
use Yeebase\TwoFactorAuthentication\Domain\ValueObjects\OneTimePassword;
use Yeebase\TwoFactorAuthentication\Domain\ValueObjects\SecretWithHmac;
use Yeebase\TwoFactorAuthentication\Exception\InvalidOtpException;
use Yeebase\TwoFactorAuthentication\Service\TwoFactorAuthenticationService;

class TwoFactorAuthenticationSetupController extends ActionController
{

    /**
     * @var Account
     */
    private $authenticatedAccount;

    /**
     * @Flow\Inject
     * @var Context
     */
    protected $securityContext;

    /**
     * @Flow\Inject
     * @var TwoFactorAuthenticationService
     */
    protected $twoFactorAuthenticationService;

    protected function initializeAction(): void
    {
        parent::initializeAction();
        $this->authenticatedAccount = $this->securityContext->getAccountByAuthenticationProviderName('Some.Package:Default');
        if ($this->authenticatedAccount === null) {
            throw new AccessDeniedException('...');
        }
    }

    public function indexAction(): void
    {
        $twoFactorAuthenticationEnabled = $this->twoFactorAuthenticationService->isTwoFactorAuthenticationEnabledFor($this->authenticatedAccount);
        $this->view->assign('2faEnabled', $twoFactorAuthenticationEnabled);
        if (!$twoFactorAuthenticationEnabled) {
            $holder = $this->authenticatedAccount->getAccountIdentifier();
            $qrCode = $this->twoFactorAuthenticationService->generateActivationQrCode($holder);
            $this->view->assignMultiple([
                'secretWithHmac' => SecretWithHmac::fromSecret($qrCode->getSecret()),
                'qrCode' => $qrCode->renderSvg(200),
            ]);
        }
    }

    public function enableAction(SecretWithHmac $secretWithHmac, OneTimePassword $otp): void
    {
        try {
            $this->twoFactorAuthenticationService->enableTwoFactorAuthentication($this->authenticatedAccount, $secretWithHmac->getSecret(), $otp);
        } catch (InvalidOtpException $exception) {
            $this->addFlashMessage('Invalid One-time Password', 'Invalid OTP', Message::SEVERITY_ERROR);
            $this->redirect('index');
        }
        $this->addFlashMessage('Two-Factor-Authentication was activated!', '2FA enabled', Message::SEVERITY_OK);
        $this->redirect('index');
    }

    public function disableAction(): void
    {
        $this->twoFactorAuthenticationService->disableTwoFactorAuthentication($this->authenticatedAccount);
        $this->addFlashMessage('Two-Factor-Authentication was deactivated!', '2FA disabled', Message::SEVERITY_NOTICE);
        $this->redirect('index');
    }
}
```

And the corresponding Template (example):

`TwoFactorAuthenticationSetup/Index.html`:
```html
<h2>Two-Factor Authentication</h2>
<f:if condition="{2faEnabled}">
	<f:then>
		<ul>
			<li>2FA is active</li>
		</ul>
		<f:form action="disable">
			<f:form.submit value="disable 2FA" />
		</f:form>
	</f:then>
	<f:else>
		<ul>
			<li>2FA is not active</li>
		</ul>
		<f:form action="enable">
			<div>
				{qrCode -> f:format.raw()}
			</div>
            <label for="otp">2FA Code</label>
            <f:form.hidden name="secretWithHmac" value="{secretWithHmac}" />
            <f:form.textfield name="otp" id="otp" additionalAttributes="{autofocus: true, pattern: '\d\d\d\d\d\d'}" required="true" title="OTP (Format: ######)" />
			<f:form.submit value="enable 2FA" />
		</f:form>
	</f:else>
</f:if>
```


In order to allow the user to setup 2FA initially, the corresponding actions have to be allowed to be called even if no 2FA is enabled for the account yet. This can be achieved with
the provided `ExcludeTwoFactorAuthenticationSetup` [Request Pattern](https://flowframework.readthedocs.io/en/stable/TheDefinitiveGuide/PartIII/Security.html#request-patterns) that
disables the 2FA authentication provider for the `setup` route configured above:

`Settings.yaml`:
```yaml
Neos:
  Flow:
    security:
      authentication:
        providers:
          # ...

          'Some.Package:2FA':
            requestPatterns:
              'Some.Package:2FASetup':
                pattern: 'Yeebase\TwoFactorAuthentication\Security\RequestPattern\ExcludeTwoFactorAuthenticationSetup'
```

*Note:* The `ExcludeTwoFactorAuthenticationSetup` will disable 2FA for _all actions_ of the configured controller, so the controller should not do any critical tasks without
further checks.

## License

This package is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments
   
This package depends on the [google2fa package](https://github.com/antonioribeiro/google2fa) for generating and validating secrets/OTP and
the [BaconQrCode](https://github.com/Bacon/BaconQrCode) for QR Code rendering
