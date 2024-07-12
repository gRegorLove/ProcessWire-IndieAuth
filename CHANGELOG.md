# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.2] - 2024-07-12
### Added
- Introspection Endpoint with HTTP Basic Authentication support
- Admin: add clients and generate client_secrets for use with Client Credentials Flow
- Admin: manually add a token with client_id and scopes -- for developer testing
- Support for clients with h-x-app [#3](https://github.com/gRegorLove/ProcessWire-IndieAuth/issues/3)

### Changed
- Updated client information discovery [#5](https://github.com/gRegorLove/ProcessWire-IndieAuth/issues/5)
- Noted refresh token expiration in the list of approved applications
- Scoped dependencies to avoid namespace collisions when other plugins have same dependencies

## [0.2.1] - 2022-08-06
### Added
- Added missing token-revocation-endpoint template
- Added `profile_name` and `profile_photo_url` fields to user template and editable profile
- Added support for clients requesting profile information

## [0.2.0] - 2022-07-04
### Changed
- Refactor: use IndieAuth protocol to sign in to applications using your domain name and optionally grant access tokens
- Follows [IndieAuth specification](https://indieauth.spec.indieweb.org/) 2022-02-12

## [0.0.1] - 2016-03-17
### Added
- Use IndieAuth protocol to sign in to your ProcessWire site

