# ProcessWire IndieAuth Module
A [ProcessWire](https://processwire.com) module to use your domain as an [IndieAuth](https://indieauth.spec.indieweb.org/) provider.

IndieAuth is an identity layer on top of OAuth 2.0. It can be used to obtain access tokens as well as authenticate users.

## Requirements
* PHP 7+
* ProcessWire 3

## Installation
The recommended method is to use the ProcessWire admin area’s module interface. If you prefer to install manually, see below.

Navigate to Modules > New. In the Module Class Name field, enter `ProcessIndieAuth`.

Continue with the [Setup](#setup) steps.

## Setup
* Copy the template files from `/extras/templates` into your `/site/templates` directory
* Verify that the plugin installed pages:
  * IndieAuth Metadata Endpoint
  * Authorization Endpoint
  * Token Endpoint
  * Token Revocation Endpoint
  * IndieAuth page under the admin’s Access menu
* Assign the `indieauth` role to any ProcessWire users that should be allowed to use IndieAuth
* Update the home page template, adding the module’s `getLinkElements` to the `<head>` element:

```html
<head>
	<?=$modules->get('ProcessIndieAuth')->getLinkElements();?>
</head>
```

This should result in three `<link>` elements in the source HTML:

```html
<head>
	<link rel="indieauth-metadata" href="/indieauth-metadata-endpoint/">
	<link rel="authorization_endpoint" href="/authorization-endpoint/">
	<link rel="token_endpoint" href="/token-endpoint/">
</head>
```

## Installation from Github
If you prefer to manually install:

* Create directory `/site/modules/ProcessIndieAuth`
* Upload the plugin files to that directory
* Install the module from the ProcessWire admin

Continue with the [Setup](#setup) steps.

## Updating Dependencies

This section is intended for developers. Follow these steps when preparing a new release of the module. If you run into an issue with the dependencies on your server, you can also follow these steps. Please consider filing an issue as well, in case the conflict is something I can improve in the module.

1. Delete the `vendor` folder
2. Run `env COMPOSER=scoped-composer.json composer install`
3. Check that `scoped-libs` folder is created and not empty
4. Run `env COMPOSER=scoped-composer.json composer install --no-dev` to remove dev dependencies
5. Run `env COMPOSER=composer.json composer dump-autoload`
6. Check that the `vendor` folder only has composer autoload files, no dev dependencies

Thanks to [this PR](https://github.com/Automattic/sensei/pull/6614) for help setting up this process.

### Testing

To run unit tests, you can use a globally installed version of phpunit, or run `composer require phpunit/phpunit ^8.4` to install it temporarily.

After running tests, be sure to remove phpunit and dev dependencies again:

1. Run `composer remove phpunit/phpunit`
2. Run `composer dump-autoload`

This gets you back to step step 5 above.

## Changelog
* [Changelog](CHANGELOG.md)

## License
Copyright 2021 by gRegor Morrill. Licensed under the MIT license https://opensource.org/licenses/MIT

