# ProcessWire IndieAuth Module
[ProcessWire](http://processwire.com) module to allow users to sign in to your site using [IndieAuth](https://indieauth.com):

> IndieAuth is a way to use your own domain name to sign in to websites. It works by linking your website to one or more authentication providers such as Twitter or Google, then entering your domain name in the login form on websites that support IndieAuth.

This module has two different functions:

## IndieAuth Authentication
After a user enters their domain name and successfully authenticates, they will be redirected back to your site and the session variable `indieauth_domain` will be set. You can then use this session variable to customize your site for the user or offer additional functionality. **Note:** The user is not logged in to ProcessWire at this point.

## ProcessWire Authentication
If you would like to allow users to log in to ProcessWire using IndieAuth, you will need to make a few changes to the user profile. 
- Add a field named `website`
- Add that field to the `user` template
- Update the `User Profile` module to make the `website` field user-editable

The user will need to set their domain name in their user profile before they can log in with IndieAuth.

## Setup
After installing the module, copy the template file `extra/templstes/indieauth.php` into your `site/templates/` directory. In the admin area, add the new indieauth template. On the "URLs" tab for the template, check "HTTPS only."

Create and publish a new ProcessWire page using this template, e.g. `https://example.com/auth/`

The included template is a minimal, sample template that covers both of the functionalities described above. You can expand the template or integrate it into your existing templates as needed. For more information about the sign-in form and how the verification works, please refer to https://indieauth.com/developers

## Notes
This module does not *create* user records if they do not exist already.
