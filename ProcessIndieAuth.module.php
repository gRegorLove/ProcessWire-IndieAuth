<?php
/**
 * This module adds IndieAuth support to ProcessWire.
 * Includes authorization endpoint and token endpoint functionality.
 * @see https://indieauth.spec.indieweb.org/
 *
 * @author gRegor Morrill, https://gregorlove.com
 * @copyright 2021 gRegor Morrill
 * @license https://opensource.org/licenses/MIT MIT
 */

declare(strict_types=1);

namespace ProcessWire;

use DateTime;
use Exception;
use PDO;
use PDOException;
use Barnabywalters\Mf2 as Mf2Helper;
use IndieAuth\AuthorizationCode;
use IndieAuth\Server;
use Mf2;

class ProcessIndieAuth extends Process implements Module, ConfigurableModule
{
    /**
     * Return information about this module
     */
    public static function getModuleInfo(): array
    {
        return [
            'title' => 'IndieAuth',
            'version' => '021',
            'author' => 'gRegor Morrill, https://gregorlove.com/',
            'summary' => 'Use your domain name as an IndieAuth provider',
            'href' => 'https://indieauth.com/',
            'requires' => [
                'PHP>=7.0',
                'ProcessWire>=3.0',
            ],
            'autoload' => true,
            'singular' => true,
            'permission' => 'page-view',
        ];
    }

    public function init(): void
    {
        require_once 'vendor/autoload.php';
        $this->addHookAfter('Session::loginSuccess', $this, 'loginSuccess');
        if ($this->auto_revoke) {
            $this->addHook('LazyCron::every12Hours', $this, 'revokeExpiredTokens');
        }
    }

    public function ___install(): void
    {
        $this->database->query("
            CREATE TABLE IF NOT EXISTS `indieauth_authorization_codes` (
                `id` int unsigned NOT NULL AUTO_INCREMENT,
                `code_id` char(16) NOT NULL DEFAULT '',
                `request` text NOT NULL,
                `code` text NOT NULL,
                `created` datetime NOT NULL,
                `used` datetime DEFAULT NULL,
                PRIMARY KEY (`id`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        $this->database->query("
            CREATE TABLE IF NOT EXISTS `indieauth_tokens` (
                `id` int unsigned NOT NULL AUTO_INCREMENT,
                `code_id` char(16) NOT NULL DEFAULT '',
                `ending` varchar(10) NOT NULL DEFAULT '',
                `client_name` varchar(255) NOT NULL DEFAULT '',
                `client_icon` varchar(255) NOT NULL DEFAULT '',
                `client_id` varchar(255) NOT NULL DEFAULT '',
                `scope` varchar(255) NOT NULL DEFAULT '',
                `issued_at` datetime NOT NULL,
                `last_accessed` datetime DEFAULT NULL,
                `expiration` datetime DEFAULT NULL,
                `token` varchar(255) NOT NULL DEFAULT '',
                `refresh_expiration` datetime DEFAULT NULL,
                `refresh_token` varchar(255) NOT NULL DEFAULT '',
                PRIMARY KEY (`id`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        $templates = file_get_contents(__DIR__ . '/data/templates.json');
        $this->importTemplates($templates);

        $fields = file_get_contents(__DIR__ . '/data/fields.json');
        $this->importFields($fields);

        $this->addProfileFields();

        # attempt to set up the indieauth-metadata page
        $endpoint = $this->pages->get('template=indieauth-metadata-endpoint');
        if ($endpoint instanceof NullPage) {
            $endpoint = new Page();
            $endpoint->template = 'indieauth-metadata-endpoint';
            $endpoint->parent = 1;
            $endpoint->title = 'IndieAuth Metadata Endpoint';
            if ($endpoint->save()) {
                $this->message(sprintf('Added page: %s', $endpoint->url));
            }
        }

        # attempt to set up the authorization-endpoint page
        $endpoint = $this->pages->get('template=authorization-endpoint');
        if ($endpoint instanceof NullPage) {
            $endpoint = new Page();
            $endpoint->template = 'authorization-endpoint';
            $endpoint->parent = 1;
            $endpoint->title = 'Authorization Endpoint';
            if ($endpoint->save()) {
                $this->message(sprintf('Added page: %s', $endpoint->url));
            }
        }

        # attempt to set up the token-endpoint page
        $endpoint = $this->pages->get('template=token-endpoint');
        if ($endpoint instanceof NullPage) {
            $endpoint = new Page();
            $endpoint->template = 'token-endpoint';
            $endpoint->parent = 1;
            $endpoint->title = 'Token Endpoint';
            if ($endpoint->save()) {
                $this->message(sprintf('Added page: %s', $endpoint->url));
            }
        }

        # attempt to set up the token-revocation-endpoint page
        $endpoint = $this->pages->get('template=token-revocation-endpoint');
        if ($endpoint instanceof NullPage) {
            $endpoint = new Page();
            $endpoint->template = 'token-revocation-endpoint';
            $endpoint->parent = 1;
            $endpoint->title = 'Token Revocation Endpoint';
            if ($endpoint->save()) {
                $this->message(sprintf('Added page: %s', $endpoint->url));
            }
        }

        # attempt to add the admin page under Access
        $parent = $this->pages->get('template=admin, name=access');
        $this->installPage('IndieAuth', $parent, 'IndieAuth');

        # attempt to add the indieauth role
        $this->installRole();

        $this->regenerateTokenSecret();

        $this->message('To complete installation, please follow the Setup directions in the readme file.');
    }

    public function ___uninstall(): void
    {
        $this->database->query("DROP TABLE IF EXISTS `indieauth_authorization_codes`");
        $this->database->query("DROP TABLE IF EXISTS `indieauth_tokens`");

        # attempt to un-publish the indieauth-metadata page
        $endpoint = $this->pages->get('template=indieauth-metadata-endpoint');
        if (!($endpoint instanceof NullPage)) {
            $endpoint->addStatus(Page::statusUnpublished);
            if ($endpoint->save()) {
                $this->message(sprintf('Unpublished page: %s', $endpoint->url));
            }
        }

        # attempt to un-publish the authorization-endpoint page
        $endpoint = $this->pages->get('template=authorization-endpoint');
        if (!($endpoint instanceof NullPage)) {
            $endpoint->addStatus(Page::statusUnpublished);
            if ($endpoint->save()) {
                $this->message(sprintf('Unpublished page: %s', $endpoint->url));
            }
        }

        # attempt to un-publish the token-endpoint page
        $endpoint = $this->pages->get('template=token-endpoint');
        if (!($endpoint instanceof NullPage)) {
            $endpoint->addStatus(Page::statusUnpublished);
            if ($endpoint->save()) {
                $this->message(sprintf('Unpublished page: %s', $endpoint->url));
            }
        }

        # attempt to un-publish the token-revocation-endpoint page
        $endpoint = $this->pages->get('template=token-revocation-endpoint');
        if (!($endpoint instanceof NullPage)) {
            $endpoint->addStatus(Page::statusUnpublished);
            if ($endpoint->save()) {
                $this->message(sprintf('Unpublished page: %s', $endpoint->url));
            }
        }

        $this->uninstallPage();
    }

    public function ___execute(): array
    {
        $table = null;
        try {
            # get total tokens
            $statement = $this->database->query('
                SELECT COUNT(*) FROm indieauth_tokens');
            $total = $statement->fetchColumn();

            if ($total == 0) {
                return compact('table');
            }

            $input = $this->wire('input');

            # set up base PageArray, used for pagination links
            $items_per_page = 10;
            $start = ($input->pageNum - 1) * $items_per_page;
            $end = $input->pageNum * $items_per_page;

            $results = new PageArray();
            $results->setTotal($total);
            $results->setLimit($items_per_page);
            $results->setStart($start);

            $statement = $this->database->query("
                SELECT
                    id
                    ,ending
                    ,client_name
                    ,client_icon
                    ,client_id
                    ,scope
                    ,issued_at
                    ,last_accessed
                    ,expiration
                FROM
                    indieauth_tokens
                LIMIT
                    {$start}, {$end}");

            if ($statement->rowCount() == 0) {
                return compact('table');
            }

            $table = $this->modules->get('MarkupAdminDataTable');
            $table->setEncodeEntities(false);
            $table->setResizable(true);
            $table->headerRow([
                'Client',
                'Scope',
                'Last Accessed',
                'Expiration',
                'Issued',
                'Ending With',
                'Actions',
            ]);

            while ($row = $statement->fetch(PDO::FETCH_ASSOC)) {
                $client_name = ($row['client_name'])
                    ? $row['client_name']
                    : $row['client_id'];

                $date_accessed = '—';
                if ($row['last_accessed']) {
                    $dt = new DateTime($row['last_accessed']);
                    $date_accessed = sprintf('<time datetime="%s" title="%s">%s</time>',
                        $dt->format('c'),
                        $dt->format('F j, Y g:ia'),
                        $dt->format('F j, Y')
                    );
                }

                $date_expiration = '—';
                if ($row['expiration']) {
                    $dt = new DateTime($row['expiration']);
                    $date_expiration = sprintf('<time datetime="%s" title="%s">%s</time>',
                        $dt->format('c'),
                        $dt->format('F j, Y g:ia'),
                        $dt->format('F j, Y')
                    );
                }

                $dt = new DateTime($row['issued_at']);
                $date_issued = sprintf('<time datetime="%s" title="%s">%s</time>',
                    $dt->format('c'),
                    $dt->format('F j, Y g:ia'),
                    $dt->format('F j, Y')
                );

                $table->row([
                    $client_name => $row['client_id'],
                    $row['scope'],
                    $date_accessed,
                    $date_expiration,
                    $date_issued,
                    $row['ending'],
                    'Revoke' => $this->page->url . 'revoke/' . $row['id'],
                ]);
            }

            return compact('table', 'results');
        } catch (PDOException $e) {
            $this->log->save('indieauth', sprintf('Error getting token overview: %s', $e->getMessage()));
            return [];
        }
    }

    /**
     * Generate a new token secret
     */
    public function ___executeTokenSecret()
    {
        $this->regenerateTokenSecret();
        $this->session->redirect($this->page->url, false);
    }

    public function ___executeAuthorization(): array
    {
        $input = $this->wire('input');
        $request = $this->session->getFor('IndieAuth', 'request');
        $client = $this->session->getfor('IndieAuth', 'client');

        # missing part of the IndieAuth session
        if (!($request && $client)) {
            $this->session->redirect($this->wire('config')->urls->admin, false);

        if (!$this->user->hasRole('indieauth')) {
            $this->message('Sorry, your account does not have the IndieAuth access role on this site.');
            $this->session->redirect($this->config->urls->admin, 302);
        }

        if ($input->requestMethod('GET')) {
            $url = $client['url'] ?? $request['client_id'];
            $name = $client['name'] ?? $request['client_id'];
            $domain = parse_url($this->urls->httpRoot, PHP_URL_HOST);
            $token_lifetime = $this->secondsToString($this->token_lifetime);
            $redirect_uri = $request['redirect_uri'];

            $logo = '';
            if ($client['logo']) {
                $logo = sprintf('<img src="%s" class="uk-width-small uk-margin-right" alt="">',
                    $client['logo']
                );
            }

            $scopes = $this->spaceSeparatedToArray($request['scope'] ?? '');

            if (!$scopes) {
                $this->headline('Authenticate');
                $this->setViewFile('views/authentication.php');
            }

            return compact(
                'url',
                'name',
                'logo',
                'domain',
                'scopes',
                'token_lifetime',
                'redirect_uri'
            );
        } elseif ($input->requestMethod('POST')) {
            $scopes = array_filter($input->post('scopes'));
            if ($scopes) {
                $request['scope'] = implode(' ', $scopes);
            }

            $this->session->setFor('IndieAuth', 'request', $request);

            if ($input->post('expiration') == 'normal') {
                $this->session->setFor('IndieAuth', 'token_lifetime', $this->token_lifetime);
            }

            $code = AuthorizationCode::fromRequest($request, $this->token_secret);
            $this->addAuthorizationCode($code);

            $url = Server::buildUrlWithQueryString($request['redirect_uri'], [
                'code' => $code->value,
                'state' => $request['state'],
                'iss' => $this->urls->httpRoot,
            ]);

            $this->session->redirect($url, false);
        }
    }

    public function ___executeCancel()
    {
        $this->cancelRequest();
    }

    public function ___executeRevoke(): array
    {
        Wire::setFuel('processHeadline', 'Revoke Access Token');
        $this->breadcrumbs->add(new Breadcrumb($this->page->url, 'IndieAuth'));

        $input = $this->wire('input');

        if ($input->requestMethod('GET')) {
            if (!($id = $input->urlSegment2)) {
                $this->handleErrorRedirect('Missing ID in URL');
            }

            try {
                $statement = $this->database->prepare('
                    SELECT
                        id
                        ,ending
                        ,client_name
                        ,client_icon
                        ,client_id
                        ,scope
                        ,issued_at
                        ,last_accessed
                        ,expiration
                    FROM
                        indieauth_tokens
                    WHERE
                        id = ?');
                $statement->execute([$id]);

                if ($statement->rowCount() == 0) {
                    $this->handleErrorRedirect('Invalid ID');
                }

                $data = $statement->fetch(PDO::FETCH_ASSOC);
                return compact('data');
            } catch (PDOException $e) {
                $this->handleErrorRedirect($e->getMessage());
            }
        } elseif ($input->requestMethod('POST')) {
            try {
                $this->revokeTokenById((int) $input->post('id'));
            } catch (PDOException $e) {
                $this->handleErrorRedirect($e->getMessage());
            }

            $this->message('Token has been revoked');
            $this->session->redirect($this->page->url, false);
        }
    }

    /**
     * Get the HTML <link> elements for authorization and token endpoints
     */
    public function getLinkElements(): string
    {
        $output = [];

        $endpoint = $this->pages->get('template=indieauth-metadata-endpoint');
        if (!($endpoint instanceof NullPage) && $endpoint->isPublic()) {
            $output[] = sprintf('<link rel="indieauth-metadata" href="%s">', $endpoint->url);
        } else {
            $output[] = '<!-- IndieAuth: no public page found with template=indieauth-metadata-endpoint -->';
        }

        $endpoint = $this->pages->get('template=authorization-endpoint');
        if (!($endpoint instanceof NullPage) && $endpoint->isPublic()) {
            $output[] = sprintf('<link rel="authorization_endpoint" href="%s">', $endpoint->url);
        } else {
            $output[] = '<!-- IndieAuth: no public page found with template=authorization-endpoint -->';
        }

        $endpoint = $this->pages->get('template=token-endpoint');
        if (!($endpoint instanceof NullPage) && $endpoint->isPublic()) {
            $output[] = sprintf('<link rel="token_endpoint" href="%s">', $endpoint->url);
        } else {
            $output[] = '<!-- IndieAuth: no public page found with template=token-endpoint -->';
        }

        return implode(PHP_EOL, $output);
    }

    /**
     * Handle GET requests to the indieauth-metadata endpoint
     */
    public function metadataEndpoint(): void
    {
        $input = $this->wire('input');

        if (!$input->requestMethod('GET')) {
            $this->httpResponse('Method not supported');
        }

        $issuer = $this->urls->httpRoot;

        $authorization_endpoint = '';
        $endpoint = $this->pages->get('template=authorization-endpoint');
        if (!($endpoint instanceof NullPage) && $endpoint->isPublic()) {
            $authorization_endpoint = $endpoint->httpUrl;
        }

        $token_endpoint = '';
        $endpoint = $this->pages->get('template=token-endpoint');
        if (!($endpoint instanceof NullPage) && $endpoint->isPublic()) {
            $token_endpoint = $endpoint->httpUrl;
        }

        $revocation_endpoint  = '';
        $endpoint = $this->pages->get('template=token-revocation-endpoint');
        if (!($endpoint instanceof NullPage) && $endpoint->isPublic()) {
            $revocation_endpoint  = $endpoint->httpUrl;
        }

        $revocation_endpoint_auth_methods_supported = ['none'];
        $code_challenge_methods_supported = ['S256'];
        $authorization_response_iss_parameter_supported = true;

        $response = compact(
            'issuer',
            'authorization_endpoint',
            'token_endpoint',
            'revocation_endpoint',
            'revocation_endpoint_auth_methods_supported',
            'code_challenge_methods_supported',
            'authorization_response_iss_parameter_supported'
        );
        $this->httpResponse($response, 200);
    }

    /**
     * Handle GET and POST requests to the authorization endpoint
     */
    public function authorizationEndpoint(): void
    {
        $input = $this->wire('input');
        $user = $this->wire('user');

        if ($input->requestMethod('GET')) {
            $request = $input->get()->getArray();
            $required_fields = array_fill_keys([
                'client_id',
                'redirect_uri',
                'state',
                'response_type',
            ], 0);

            # verify required fields
            $missing_fields = array_diff_key($required_fields, $request);
            if (count($missing_fields) > 0) {
                $response = sprintf('Missing required request parameters: %s',
                    implode(', ', array_keys($missing_fields))
                );
                $this->httpResponse($response);
            }

            if (!Server::isClientIdValid($request['client_id'])) {
                $this->httpResponse('client_id is invalid');
            }

            if (!filter_var($request['redirect_uri'], FILTER_VALIDATE_URL)) {
                $this->httpResponse('redirect_uri is invalid');
            }

            $request['client_id'] = Server::canonizeUrl($request['client_id']);
            $request['redirect_uri'] = Server::canonizeUrl($request['redirect_uri']);
            $client = $this->getClientInfo($request['client_id']);

            if (!Server::isRedirectUriAllowed($request['redirect_uri'], $request['client_id'], $client['redirect_uri'])) {
                $this->httpResponse('mismatched redirect_uri');
            }

            ## Safe to redirect to redirect_uri now

            /**
             * verify response_type
             * `id` is for backwards compatibility
             */
            if (!in_array($request['response_type'], ['id', 'code'])) {
                $this->redirectHttpResponse($request['redirect_uri'], [
                    'error' => 'unsupported_response_type',
                    'error_description' => 'response_type must have value "code"',
                ]);
            }

            # verify code_challenge_method if PKCE request
            if (array_key_exists('code_challenge', $request)) {
                if (!array_key_exists('code_challenge_method', $request) || $request['code_challenge_method'] != 'S256') {
                    $this->redirectHttpResponse($request['redirect_uri'], [
                        'error' => 'invalid_request',
                        'error_description' => 'code_challenge_method must have value "S256". "plain" is not supported by this server.',
                    ]);
                }
            }

            ## IndieAuth request is valid

            $this->session->setFor('IndieAuth', 'request', $request);
            $this->session->setFor('IndieAuth', 'client', $client);
            $this->session->setFor('IndieAuth', 'user_id', $this->user->id);

            if ($user->isLoggedIn()) {
                $moduleID = $this->modules->getModuleID($this);
                $admin = $this->pages->get('process=' . $moduleID);
                $this->session->redirect($admin->url . 'authorization', false);
            }

            # redirct to ProcessWire login
            $this->session->redirect($this->wire('config')->urls->admin, false);

        } elseif ($input->requestMethod('POST')) {
            $request = $input->post()->getArray();
            if ($this->isRedeemAuthorizationCodeRequest($request)) {
                $this->redeemAuthorizationCode($request);
            }

            # default: invalid request
            $this->httpResponse([
                'error' => 'invalid_request',
                'error_description' => 'Invalid request',
            ]);
        }
    }

    /**
     * Handle token endpoint requests
     */
    public function tokenEndpoint(): void
    {
        $input = $this->wire('input');

        if ($input->requestMethod('GET')) {
            # backcompat: overloaded token endpoint can introspect access tokens
            $bearer_token = $this->getBearerToken();
            if (!$bearer_token) {
                $this->httpResponse('Error: Authorization header not found');
            }

            $response = $this->verifyToken($bearer_token);
            if (!$response) {
                $this->httpResponse(['active' => false], 200);
            }

            $this->httpResponse($response, 200);
        } elseif ($input->requestMethod('POST')) {
            $request = $input->post()->getArray();

            if ($this->isRedeemAuthorizationCodeRequest($request)) {
                $this->redeemAuthorizationCode($request);
            }

            if ($this->isRefreshAccessTokenRequest($request)) {
                $this->refreshAccessToken($request);
            }

            # backcompat: overloaded token endpoint with `action=revoke` request
            if (array_intersect_key($request, array_fill_keys(['action', 'token'], ''))) {
                $this->tokenRevocationEndpoint();
            }

            # default: invalid request
            $this->httpResponse([
                'error' => 'invalid_request',
                'error_description' => 'Invalid request',
            ]);
        }
    }

    /**
     * Handle token revocation requests
     * This endpoint does not currently require authorization
     * @see https://indieauth.spec.indieweb.org/#token-revocation
     */
    public function tokenRevocationEndpoint(): void
    {
        $input = $this->wire('input');

        if ($input->requestMethod('GET')) {
            $this->httpResponse('Method not supported', 405, ['Allow' => 'POST']);
        }

        $request = $input->post()->getArray();

        $token_request = $request['token'] ?? null;
        if (!$token_request) {
            $this->httpResponse([
                'error' => 'invalid_request',
                'error_description' => 'Missing `token` parameter',
            ]);
        }

        /**
         * `action=revoke` is backcompat.
         * Effectively ignored now, but error if `action` is provided
         * and has an unexpected value.
         */
        $action = $request['action'] ?? null;
        if ($action && ($action != 'revoke')) {
            $this->httpResponse([
                'error' => 'invalid_request',
                'error_description' => 'Invalid `action` parameter. Note that `action` is no longer needed for token revocation requests.',
            ]);
        }

        $token = $this->lookupToken($token_request);
        if ($token && $this->revokeTokenById((int) $token['id'])) {
            $this->log->save('indieauth', sprintf('Revoked access token for %s with scope "%s"',
                $token['client_id'],
                $token['scope']
            ));
        }

        # always respond with HTTP 200, even if it was not successful
        $this->httpResponse('', 200);
    }

    /**
     * Verify an access token
     *
     * This method is intended to be used by other software
     * interacting with this endpoint, e.g. the ProcessWire-Micropub
     * module will use it to verify tokens in Micropub requests.
     *
     * If token is valid, return an array that follows the spec's
     * "Access Token Verification Response" section. Otherwise
     * return null.
     *
     * If the Token Introspection Endpoint is introduced, a separate
     * method could call this and then return the JSON.
     */
    public function verifyToken(string $bearer_token): ?array
    {
        $token = $this->lookupToken($bearer_token);
        if (!$token) {
            return null;
        }

        $this->updateTokenLastAccessed((int) $token['id']);

        $response = [
            'me' => $this->wire('urls')->httpRoot,
            'client_id' => $token['client_id'],
            'scope' => $token['scope'],
            'active' => true,
        ];

        if ($token['expiration']) {
            $dt_expiration = new DateTime($token['expiration']);
            $dt_current = new DateTime();
            if ($dt_current > $dt_expiration) {
                $response['active'] = false;
            } else {
                $response['expires_in'] = $dt_expiration->getTimeStamp() - $dt_current->getTimeStamp();
            }
        }

        return $response;
    }

    private function isRedeemAuthorizationCodeRequest(array $request): bool
    {
        $required_fields = array_fill_keys([
            'grant_type',
            'code',
            'client_id',
            'redirect_uri',
        ], 0);

        # verify required fields
        $missing_fields = array_diff_key($required_fields, $request);
        if (count($missing_fields) > 0) {
            return false;
        }

        return true;
    }

    /**
     * Handle an authorization code sent to one of the endpoints
     * @see https://indieauth.spec.indieweb.org/#redeeming-the-authorization-code
     */
    private function redeemAuthorizationCode(array $request): void
    {
        /*$required_fields = array_fill_keys([
            'grant_type',
            'code',
            'client_id',
            'redirect_uri',
        ], 0);

        # verify required fields
        $missing_fields = array_diff_key($required_fields, $request);
        if (count($missing_fields) > 0) {
            $this->httpResponse([
                'error' => 'invalid_request',
                'error_description' => sprintf('Missing required request parameters: %s',
                    implode(', ', array_keys($missing_fields))
                )
            ]);
        }*/

        # default grant_type if none provided
        if (!array_key_exists('grant_type', $request)) {
            $request['grant_type'] = 'authorization_code';
        }

        # verify grant_type
        if ($request['grant_type'] != 'authorization_code') {
            $this->httpResponse([
                'error' => 'unsupported_grant_type',
                'error_description' => 'grant_type must be "authorization_code"'
            ]);
        }

        $decoded = $this->verifyCode($request);

        $client_id = $decoded['client_id'] ?? '';
        $scope = $decoded['scope'] ?? '';

        $scopes = $this->spaceSeparatedToArray($decoded['scope'] ?? '');

        # authorization_code has scope(s), generate an access token
        if ($scope) {
            $token_data = $this->addToken($decoded);
            if (!$token_data) {
                $this->httpResponse([
                    'error' => 'internal_error',
                    'error_description' => 'An unexpected error occurred while redeeming the authorization code',
                ], 500);
            }

            $response = array_merge(
                [
                    'me' => $this->wire('urls')->httpRoot,
                    'scope' => $scope,
                ],
                $token_data
            );

            if (in_array('profile', $scopes)) {
                $response = $this->addProfileToResponse($response);
            }

            $this->session->removeAllFor('IndieAuth');
            $this->log->save('indieauth', sprintf('Granted access token to %s with scope "%s"', $client_id, $scope));
            $this->httpResponse($response, 200);
        }

        # authentication-only response
        $me = $this->wire('urls')->httpRoot;
        $response = compact('me');

        if (in_array('profile', $scopes)) {
            $response = $this->addProfileToResponse($response);
        }

        $this->session->removeAllFor('IndieAuth');
        $this->log->save('indieauth', sprintf('Signed in to %s as %s', $request['client_id'], $me));
        $this->httpResponse($response, 200);
    }

    private function isRefreshAccessTokenRequest(array $request): bool
    {
        $required_fields = array_fill_keys([
            'grant_type',
            'refresh_token',
            'client_id',
        ], 0);

        # verify required fields
        $missing_fields = array_diff_key($required_fields, $request);
        if (count($missing_fields) > 0) {
            return false;
        }

        return true;
    }

    private function refreshAccessToken(array $request): void
    {
        /*$required_fields = array_fill_keys([
            'grant_type',
            'refresh_token',
            'client_id',
        ], 0);

        # verify required fields
        $missing_fields = array_diff_key($required_fields, $request);
        if (count($missing_fields) > 0) {
            $this->httpResponse([
                'error' => 'invalid_request',
                'error_description' => sprintf('Missing required request parameters: %s',
                    implode(', ', array_keys($missing_fields))
                )
            ]);
        }*/

        # verify grant_type
        if ($request['grant_type'] != 'refresh_token') {
            $this->httpResponse([
                'error' => 'unsupported_grant_type',
                'error_description' => 'grant_type must be "refresh_token"'
            ]);
        }

        $original_token = $this->lookupRefreshToken($request['refresh_token'], $request['client_id']);
        if (!$original_token) {
            $this->httpResponse([
                'error' => 'forbidden',
                'error_description' => 'Invalid refresh token',
            ], 403);
        }

        $token_data = $this->updateToken((int) $original_token['id']);
        if (!$token_data) {
            $this->httpResponse([
                'error' => 'internal_error',
                'error_description' => 'An unexpected error occurred while refreshing the access token',
            ], 500);
        }

        $response = array_merge(
            [
                'me' => $this->wire('urls')->httpRoot,
                'scope' => $original_token['scope'],
            ],
            $token_data
        );

        $this->log->save('indieauth',
            sprintf('Granted refreshed access token to %s with scope "%s"',
                $request['client_id'],
                $original_token['scope']
            )
        );
        $this->httpResponse($response, 200);
    }

    /**
     * Get the Bearer token from request headers
     */
    private function getBearerToken(): ?string
    {
        $headers = \getallheaders();

        if (array_key_exists('Authorization', $headers) && preg_match('/^Bearer (.+)/', $headers['Authorization'], $matches)) {
            return $matches[1];
        }

        return null;
    }

    private function verifyCode(array $request): array
    {
        $decoded = AuthorizationCode::decode($request['code'] ?? '', $this->token_secret);
        if (!$decoded) {
            $this->httpResponse([
                'error' => 'invalid_grant',
                'error_description' => 'code is not valid'
            ]);
        }

        $id = $decoded['id'] ?? '';
        if ($this->isCodeUsed($id)) {
            $this->revokeTokensByCodeId($id);
            $this->httpResponse([
                'error' => 'invalid_grant',
                'error_description' => 'code is not valid'
            ]);
        }

        $original_request = $this->lookupCodeRequest($id);
        if (!$original_request) {
            $this->httpResponse([
                'error' => 'invalid_grant',
                'error_description' => 'code is not valid'
            ]);
        }

        $code_challenge = $original_request['code_challenge'] ?? null;
        $code_verifier = $request['code_verifier'] ?? null;

        if ($code_challenge && !$code_verifier) {
            $this->httpResponse([
                'error' => 'invalid_grant',
                'error_description' => 'Missing parameter: code_verifier'
            ]);
        }

        if (!$code_challenge && $code_verifier) {
            $this->httpResponse([
                'error' => 'invalid_grant',
                'error_description' => 'code_verifier was provided, but the authorization request did not include a code_challenge'
            ]);
        }

        if ($code_challenge && $code_verifier) {
            if (!Server::isCodeVerifierValid($code_verifier, $code_challenge)) {
                $this->httpResponse([
                    'error' => 'invalid_grant',
                    'error_description' => 'code_verifier is not valid'
                ]);
            }
        }

        # canonize URLs
        $request['client_id'] = Server::canonizeUrl($request['client_id']);
        $request['redirect_uri'] = Server::canonizeUrl($request['redirect_uri']);

        # verify client_id
        $original_client_id = $decoded['client_id'] ?? '';
        if ($request['client_id'] !== $original_client_id) {
            $this->httpResponse([
                'error' => 'invalid_client',
                'error_description' => 'client_id in request does not match the authorization code'
            ]);
        }

        # verify redirect_uri
        $original_redirect_uri = $decoded['redirect_uri'] ?? '';
        if ($request['redirect_uri'] !== $original_redirect_uri) {
            $this->httpResponse([
                'error' => 'invalid_grant',
                'error_description' => 'redirect_uri in request does not match the authorization code'
            ]);
        }

        $this->useAuthorizationCode($id);

        return $decoded;
    }

    /**
     * Customize the loginSuccess for authorization flow
     */
    protected function loginSuccess(HookEvent $event): void
    {
        if ($this->session->getFor('IndieAuth', 'request')) {

            if (!$this->user->hasRole('indieauth')) {
                $this->message('Sorry, your account does not have the IndieAuth access role on this site.');
                $this->session->redirect($this->config->urls->admin, 302);
            }

            $moduleID = $this->modules->getModuleID($this);
            $admin = $this->pages->get('process=' . $moduleID);
            $this->session->redirect($admin->url . 'authorization', false);
        }
    }

    private function addAuthorizationCode(AuthorizationCode $code): bool
    {
        try {
            $statement = $this->database->prepare('
                INSERT INTO indieauth_authorization_codes SET
                    code_id = ?
                    ,request = ?
                    ,code = ?
                    ,created = NOW()');

            return $statement->execute([
                $code->code_id,
                json_encode($code->request),
                $code->value,
            ]);
        } catch (PDOException $e) {
            return false;
        }
    }

    private function useAuthorizationCode(string $code_id): bool
    {
        try {
            $statement = $this->database->prepare('
                UPDATE indieauth_authorization_codes SET
                    used = NOW()
                WHERE
                    code_id = ?');

            return $statement->execute([
                $code_id
            ]);
        } catch (PDOException $e) {
            return false;
        }
    }

    /**
     * Check if authorization code has already been used
     */
    private function isCodeUsed(string $id): bool
    {
        try {
            $statement = $this->database->prepare('
                SELECT
                    used
                FROM
                    indieauth_authorization_codes
                WHERE
                    code_id = ?
                    AND used IS NOT NULL');
            $statement->execute([$id]);

            return ($statement->rowCount() > 0);
        } catch (PDOException $e) {
            $this->log->save('indieauth', sprintf('Error checking if code has been used: %s', $e->getMessage()));
            return false;
        }
    }

    /**
     * Lookup authorization code request by ID
     */
    private function lookupCodeRequest(string $id): ?array
    {
        try {
            $statement = $this->database->prepare('
                SELECT
                    request
                FROM
                    indieauth_authorization_codes
                WHERE
                    code_id = ?');
            $statement->execute([$id]);

            if ($statement->rowCount() == 0) {
                $this->log->save('indieauth', sprintf('Unable to find code request by id: %s', $id));
                return null;
            }

            return json_decode($statement->fetchColumn(), true);
        } catch (PDOException $e) {
            $this->log->save('indieauth', sprintf('Error looking up code request: %s', $e->getMessage()));
            return null;
        }
    }

    private function addToken(array $authorization): ?array
    {
        try {
            $token = bin2hex(random_bytes(128));
            $refresh_token = bin2hex(random_bytes(128));

            $response = [
                'token_type' => 'Bearer',
                'access_token' => $token,
                'refresh_token' => $refresh_token,
            ];

            $expiration = null;
            $refresh_expiration = null;
            $token_lifetime = $authorization['token_lifetime'] ?? null;
            if ($token_lifetime) {
                $dt = new DateTime();
                $dt->modify('+ ' . $token_lifetime . ' seconds');
                $expiration = $dt->format('Y-m-d H:i:s');
                $response['expires_in'] = $token_lifetime;

                $dt->modify('+ ' . $token_lifetime . ' seconds');
                $refresh_expiration = $dt->format('Y-m-d H:i:s');
            }

            $statement = $this->database->prepare('
                INSERT INTO indieauth_tokens SET
                    code_id = ?
                    ,ending = ?
                    ,client_name = ?
                    ,client_icon = ?
                    ,client_id = ?
                    ,`scope` = ?
                    ,issued_at = NOW()
                    ,expiration = ?
                    ,token = ?
                    ,refresh_expiration = ?
                    ,refresh_token = ?');

            $statement->execute([
                $authorization['id'],
                substr($token, -7),
                $authorization['client_name'] ?? '',
                $authorization['client_logo'] ?? '',
                $authorization['client_id'] ?? '',
                $authorization['scope'] ?? '',
                $expiration,
                hash('sha256', $token),
                $refresh_expiration,
                hash('sha256', $refresh_token),
            ]);

            return $response;
        } catch (PDOException $e) {
            $this->log->save('indieauth', sprintf('Error adding token: %s', $e->getMessage()));
            return null;
        }
    }

    private function updateToken(int $id): ?array
    {
        try {
            $dt = new DateTime('+ ' . $this->token_lifetime . ' seconds');
            $expiration = $dt->format('Y-m-d H:i:s');
            $token = bin2hex(random_bytes(128));

            $dt->modify('+ ' . $this->token_lifetime . ' seconds');
            $refresh_expiration = $dt->format('Y-m-d H:i:s');
            $refresh_token = bin2hex(random_bytes(128));

            $response = [
                'token_type' => 'Bearer',
                'access_token' => $token,
                'refresh_token' => $refresh_token,
                'expires_in' => $this->token_lifetime,
            ];

            $statement = $this->database->prepare('
                UPDATE indieauth_tokens SET
                    ending = ?
                    ,expiration = ?
                    ,token = ?
                    ,refresh_expiration = ?
                    ,refresh_token = ?
                WHERE
                    id = ?');

            $statement->execute([
                substr($token, -7),
                $expiration,
                hash('sha256', $token),
                $refresh_expiration,
                hash('sha256', $refresh_token),
                $id,
            ]);

            return $response;
        } catch (PDOException $e) {
            $this->log->save('indieauth', sprintf('Error updating token: %s', $e->getMessage()));
            return null;
        }
    }

    /**
     * Update last_accessed datetime for token
     */
    private function updateTokenLastAccessed(int $id): bool
    {
        try {
            $statement = $this->database->prepare('
                UPDATE indieauth_tokens SET
                    last_accessed = NOW()
                WHERE
                    id = ?');

            return $statement->execute([$id]);
        } catch(PDOException $e) {
            $this->log->save('indieauth', sprintf('Error updating token last_accessed: %s', $e->getMessage()));
            return false;
        }
    }

    /**
     * Lookup token by un-hashed token value
     * @param string $token un-hashed token
     */
    private function lookupToken(string $token): ?array
    {
        try {
            $statement = $this->database->prepare('
                SELECT
                    id
                    ,ending
                    ,client_name
                    ,client_icon
                    ,client_id
                    ,scope
                    ,issued_at
                    ,last_accessed
                    ,expiration
                FROM
                    indieauth_tokens
                WHERE
                    token = ?
                    AND (
                        expiration IS NULL
                        OR expiration > NOW()
                    )');

            $statement->execute([
                hash('sha256', $token),
            ]);

            if ($statement->rowCount() === 0) {
                $this->log->save('indieauth', sprintf('Unable to find token ending with "%s"', substr($token, -7)));
                return null;
            }

            return $statement->fetch(PDO::FETCH_ASSOC);
        } catch (PDOException $e) {
            $this->log->save('indieauth', sprintf('Error looking up token: %s', $e->getMessage()));
            return null;
        }
    }

    /**
     * Lookup refresh token by un-hashed token value
     * @param string $refresh_token un-hashed token
     * @param string $client_id
     */
    private function lookupRefreshToken(string $refresh_token, string $client_id): ?array
    {
        try {
            $statement = $this->database->prepare('
                SELECT
                    id
                    ,ending
                    ,client_name
                    ,client_icon
                    ,client_id
                    ,scope
                    ,issued_at
                    ,last_accessed
                    ,expiration
                FROM
                    indieauth_tokens
                WHERE
                    refresh_token = ?
                    AND client_id = ?
                    AND (
                        refresh_expiration IS NULL
                        OR refresh_expiration > NOW()
                    )');

            $statement->execute([
                hash('sha256', $refresh_token),
                $client_id,
            ]);

            if ($statement->rowCount() === 0) {
                $this->log->save('indieauth', sprintf('Unable to find refresh token ending with "%s"', substr($refresh_token, -7)));
                return null;
            }

            return $statement->fetch(PDO::FETCH_ASSOC);
        } catch (PDOException $e) {
            $this->log->save('indieauth', sprintf('Error looking up refresh token: %s', $e->getMessage()));
            return null;
        }
    }

    private function revokeTokenById(int $id): bool
    {
        try {
            $statement = $this->database->prepare('
                DELETE FROM indieauth_tokens
                WHERE
                    id = ?');

            return $statement->execute([$id]);
        } catch(PDOException $e) {
            $this->log->save('indieauth', sprintf('Error revoking token: %s', $e->getMessage()));
            return false;
        }
    }

    private function revokeTokensByCodeId(string $code_id): bool
    {
        try {
            $statement = $this->database->prepare('
                DELETE FROM indieauth_tokens
                WHERE
                    code_id = ?');

            return $statement->execute([$code_id]);
        } catch(PDOException $e) {
            $this->log->save('indieauth', sprintf('Error revoking tokens: %s', $e->getMessage()));
            return false;
        }
    }

    public function revokeExpiredTokens()
    {
        try {
            return $this->database->query('
                DELETE FROM indieauth_tokens
                WHERE
                    expiration <= NOW()
                    AND (
                        refresh_expiration IS NULL
                        OR refresh_expiration <= NOW()
                    )');
        } catch(PDOException $e) {
            $this->log->save('indieauth', sprintf('Error revoking tokens: %s', $e->getMessage()));
            return false;
        }
    }

    /**
     * Reset the IndieAuth session and redirect to the redirect_uri
     * with an access_denied error.
     */
    private function cancelRequest(): void
    {
        $request = $this->session->getFor('IndieAuth', 'request');
        $this->session->removeAllFor('IndieAuth');

        $url = Server::buildUrlWithQueryString($request['redirect_uri'], [
            'error' => 'access_denied',
            'error_description' => 'authorization request cancelled by the user',
            'state' => $request['state'],
        ]);
        $this->session->redirect($url, false);
    }

    /**
     * When `profile` scope is requested, add profile to the response body
     * If the user's `profile_name` is not set, profile will not be included
     * in the response body.
     *
     * TODO: optionally add profile photo
     * @see https://indieauth.spec.indieweb.org/#profile-information
     */
    private function addProfileToResponse(array $response): array
    {
        $user_id = $this->session->getFor('IndieAuth', 'user_id');
        $user = $this->users->get($user_id);

        if (!$user->get('profile_name')) {
            $this->log->save('indieauth', 'Missing profile name in user account');
            return $response;
        }

        return array_merge(
            $response,
            [
                'profile' => [
                    'name' => $user->get('profile_name'),
                    'url' => $this->wire('urls')->httpRoot,
                    'photo' => $user->get('profile_photo_url'),
                ],
            ]
        );
    }

    private function redirectHttpResponse(string $redirect_uri, array $queryParams): void
    {
        $url = Server::buildUrlWithQueryString($redirect_uri, $queryParams);
        $this->session->redirect($url, false);
    }

    private function httpResponse($response, int $http_status = 400, array $headers = []): void
    {
        foreach ($headers as $key => $value) {
            $header = sprintf('%s: %s', $key, $value);
            header($header);
        }

        if ($http_status === 401) {
            header(sprintf('WWW-Authenticate: Bearer realm="%s"', $this->urls->httpRoot));
        }

        http_response_code($http_status);

        if (is_array($response)) {
            $flags = 0;
            if (array_key_exists('pretty', $_GET)) {
                $flags = JSON_PRETTY_PRINT;
            }
            header('Content-Type: application/json; charset=UTF-8');
            echo json_encode($response, $flags);
        } else {
            echo $response;
        }

        exit;
    }

    private function getClientInfo(string $url): array
    {
        $info = array_fill_keys([
            'name',
            'url',
            'logo',
        ], '');

        $info['name'] = parse_url($url, PHP_URL_HOST);
        $info['url'] = $url;
        $info['redirect_uri'] = [];

        $http = new WireHttp();
        $response = $http->get($url);
        if (false === $response) {
            $this->log->save('indieauth',
                sprintf('Error getting client info for %s: %s',
                    $url,
                    $http->getError()
                )
            );
            return $info;
        }

        $mf = Mf2\parse($response, $url);
        $info['redirect_uri'] = $mf['rels']['redirect_uri'] ?? [];

        $apps = Mf2Helper\findMicroformatsByType($mf, 'h-app');

        if (!$apps) {
            return $info;
        }

        $app = reset($apps);

        if (Mf2Helper\hasProp($app, 'name')) {
            $info['name'] = Mf2Helper\getPlaintext($app, 'name');
        }

        if (Mf2Helper\hasProp($app, 'logo')) {
            $info['logo'] = Mf2Helper\getPlaintext($app, 'logo');
        }

        return $info;
    }

    private function spaceSeparatedToArray(string $input): array
    {
        if (!$input) {
            return [];
        }

        return array_filter(
            array_map(
                'trim',
                explode(' ', $input)
            )
        );
    }

    private function secondsToString(int $input): string
    {
        $minute = 60;
        $hour = 60 * $minute;
        $day = 24 * $hour;

        $days = floor($input / $day);
        $hours = floor(($input % $day) / $hour);
        $minutes = floor(($input % $hour) / $minute);
        $seconds = ceil($input % $minute);

        $segments = [
            'day' => $days,
            'hour' => $hours,
            'minute' => $minutes,
            'second' => $seconds,
        ];

        foreach ($segments as $name => $value) {
            if ($value > 0) {
                $timeParts[] = $value. ' '.$name.($value == 1 ? '' : 's');
            }
        }

        return implode(', ', $timeParts);
    }

    /**
     * Perform a redirect with an error message
     * @param string $message
     * @param string $url
     */
    private function handleErrorRedirect(string $message = '', string $url = ''): void
    {
        if (!$url) {
            $url = $this->page->url;
        }

        if (!$message) {
            $message = 'Unexpected error. Developers, please see Setup &gt; Logs &gt; “indieauth” for more information.';
        }

        $this->error($message);
        $this->session->redirect($url, false);
    }

    private function regenerateTokenSecret(): void
    {
        $this->modules->saveConfig($this, 'token_secret', bin2hex(random_bytes(128)));
        $this->message('IndieAuth secret re-generated');
    }

    /**
     * Import templates from JSON or array
     * @param string|array $json
     * @return bool
     * @see https://processwire.com/talk/topic/9007-utility-to-help-generate-module-install-function/?do=findComment&comment=86995
     */
    private function importTemplates($json): void
    {
        $data = is_array($json) ? $json : wireDecodeJSON($json);

        foreach ($data as $name => $template_data) {
            # ensure no template ID to avoid conflicts
            unset($template_data['id']);

            $template = $this->templates->get($name);

            # template doesn't exist already; create it
            if (!$template) {
                $template = new Template();
                $template->name = $name;

                # import the data for the template
                $template->setImportData($template_data);

                $fieldgroup = $template->fieldgroup;
                $fieldgroup->save();
                $fieldgroup->saveContext();
                $template->save();

                # no fieldgroup set for template
                if (!$template->fieldgroup_id) {
                    $template->setFieldgroup($fieldgroup);
                    $template->save();
                }

                $this->message(sprintf('Added template: %s', $name));
            } else {
                $this->message(sprintf('Skipped existing template: %s', $name));
            }
        }
    }

    /**
     * Import templates from JSON or array
     * @param string|array $json
     * @see https://processwire.com/talk/topic/9007-utility-to-help-generate-module-install-function/?do=findComment&comment=86995
     */
    private function importFields($json): void
    {
        $data = is_array($json) ? $json : wireDecodeJSON($json);

        foreach ($data as $name => $field_data) {
            # get rid of the ID so it doesn't conflict
            unset($field_data['id']);

            # field doesn't exist already; create it
            if (!$this->fields->get($name)) {
                $field = new Field();
                $field->name = $name;

                # import the data for the field
                $field->setImportData($field_data);
                $field->save();

                $this->message(sprintf('Added field: %s', $name));
            } else {
                $this->message(sprintf('Skipped existing field: %s', $name));
            }
        }
    }

    private function addProfileFields(): void
    {
        # attempt to add profile fields to user template
        $fieldgroup = $this->templates->get('user')->fieldgroup;
        $fields_to_add = [
            'profile_name',
            'profile_photo_url',
        ];

        foreach ($fields_to_add as $name) {
            if (!$fieldgroup->has($name)) {
                $fieldgroup->add($name);
                if ($fieldgroup->save()) {
                    $this->message(sprintf('Added field: %s', $name));
                }
            }
        }

        # attempt to make new profile fields editable by user
        $profileFields = $this->modules->get('ProcessProfile')->profileFields;
        if ($missing_fields = array_diff($fields_to_add, $profileFields)) {
            foreach ($missing_fields as $name) {
                $profileFields[] = $name;
            }
            $this->modules->saveConfig('ProcessProfile', compact('profileFields'));
            $this->message('Updated user profile fields', Notice::debug);
        }
    }

    private function installRole(): void
    {
        $role = $this->roles->get('indieauth');
        if ($role instanceof NullPage) {
            $this->roles->add('indieauth');
            $this->message('Added role: indieauth');
        }
    }

    private function debug($var, bool $as_html = false): void
    {
        if ($as_html) {
            echo '<pre>';
        } else {
            header('Content-Type: text/plain; charset=utf8');
        }

        if (is_array($var) || is_object($var)) {
            print_r($var);
        } else {
            echo $var;
        }

        echo "\n\nvar dump:\n";
        var_dump($var);

        if ($as_html) {
            echo '</pre>';
        }

        exit;
    }
}

