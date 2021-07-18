# ProcessWire IndieAuth Module
**Version 0.2.0 is under development currently.**

A [ProcessWire](http://processwire.com) module to use your domain as an [IndieAuth](https://indieauth.spec.indieweb.org/) provider.

IndieAuth is an identity layer on top of OAuth 2.0. It can be used to obtain access tokens as well as authenticate users.

## Requirements
* PHP 7+
* ProcessWire 3

## Installation
* Upload the plugin files to the `/site/modules` directory
* Install the module from the ProcessWire admin
* Copy the template files from `/extras/templates` into your `/site/templates` directory
* Verify that the plugin installed public pages "Authorization Endpoint" and "Token Endpoint" as well as an admin page "IndieAuth" under the admin’s Access menu.
* Update the home page template, adding the module’s `getLinkElements` to the `<head>` element:

```html
<head>
	<?=$modules->get('ProcessIndieAuth')->getLinkElements();?>
</head>
```

This should result in two `<link>` elements in the source HTML:

```html
<head>
	<link rel="authorization_endpoint" href="/authorization-endpoint/">
	<link rel="token_endpoint" href="/token-endpoint/">
</head>
```
# License
Copyright 2021 by gRegor Morrill. Licensed under the MIT license https://opensource.org/licenses/MIT

