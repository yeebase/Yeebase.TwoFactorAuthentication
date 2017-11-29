# Yeebase.TwoFactorAuthentication

The Yeebase.TwoFactorAuthentication Flow package contains extensions to the Flow authentication mechanism
that let you implement Two-Factor-Authentication easily.

It depends on the Google2FA package https://github.com/antonioribeiro/google2fa

## Installation

Just add "yeebase/twofactorauthentication" as dependency to your composer.json and run a "composer update" in your project's root folder
or simply execute:
```
composer require yeebase/twofactorauthentication
```
from your project's root.

## Configuration
The following part describes the integration of the Two-Factor-Authentication package into an existing Flow Application.
The package can be integrated into a working application without applying any data migrations to the existing user base.
Existing users will simply be treated as if Two-Factor-Authentication is disabled for them.

### Provider
Instead of using the default UsernamePasswordProvider, adapt your settings to use the following provider instead: `Yeebase\TwoFactorAuthentication\Security\Authentication\Provider\TwoFactorAuthenticationProvider`

### Controllers and Templates
This package brings two abstract controllers that contain all the methods necessary for login with and management of Two-Factor-Authentication.

Instead of inheriting from the basic `AbstractAuthenticationController`, you should now inherit from `AbstractTwoFactorAuthenticationController` in your LoginController.
The template of your login action should be adapted as described in the `TwoFactorUsernamePasswordToken` class.
Additionally, you need to add a template for the `insertSecretAction` where the user can insert a secret.

For the management of Two-Factor-Authentication you can inherit from the `AbstractAuthenticationManagementController`.
Using this controller, it is necessary to provide exactly one template for the `configureAction`.
When 2FA is disabled, it passes an `activationQrCode`-parameter to the template that holds the QR-Code which can be scanned by a GoogleAuthenticator.
When 2FA is enabled, it does not pass any parameters to the template. From this point on, either the `enableAction` or the `disableAction` should be called
with a `secret`-parameter given by the user to enable/disable 2FA.

### Settings
For the application to run, you should at least provide an `applicationName` which will be displayed in the Authenticator-App of the user.
Furthermore, the `authenticationEntryPoint` should be specified. It configures where the user is redirected to, when he or she has to insert the secret for 2FA.
This should usually be the LoginController of your package (if you inherited from `AbstractTwoFactorAuthenticationController` as described above).
