<?php
/**
 * This class handles IndieAuth Server validation and normalization
 *
 * @author gRegor Morrill, https://gregorlove.com
 * @copyright 2021 gRegor Morrill
 * @license https://opensource.org/licenses/MIT MIT
 */

declare(strict_types=1);

namespace IndieAuth;

use IndieAuth\Libs\{
    Barnabywalters\Mf2 as Mf2Helper,
    Mf2
};
use ProcessWire\WireHttp;

final class Server
{
    /**
     * Get client information
     * First check if the client_id itself is the info (JSON)
     * Fallback to checking for h-app or h-x-app
     *
     * @see https://github.com/indieweb/indieauth/issues/133
     */
    public static function getClientInfo(string $client_id): array
    {
        $headers = static::fetchHead($client_id, ['content-type']);

        $is_json = false;
        if ($headers) {
            if (static::hasContentType('application/json', $headers['content-type'])) {
                $is_json = true;
            }
        }

        $content = static::fetchBody($client_id);

        if ($is_json) {
            $json = json_decode($content, true);
            if ($json) {
                return [
                    'name' => $json['client_name'] ?? '',
                    'url' => $json['client_uri'] ?? '',
                    'logo' => $json['logo_uri'] ?? '',
                    'redirect_uris' => $json['redirect_uris'] ?? [],
                ];
            }
        }

        $info = array_fill_keys([
            'name',
            'url',
            'logo',
        ], '');

        $info['name'] = parse_url($client_id, PHP_URL_HOST);
        $info['url'] = $client_id;
        $info['redirect_uris'] = [];

        $mf2 = Mf2\parse($content, $client_id);
        $info['redirect_uris'] = $mf2['rels']['redirect_uri'] ?? [];

        $apps = Mf2Helper\findMicroformatsByType($mf2, 'h-app');
        if (!$apps) {
            $apps = Mf2Helper\findMicroformatsByType($mf2, 'h-x-app');
        }

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

    /**
     * @see https://indieauth.spec.indieweb.org/#client-identifier
     */
    public static function isClientIdValid(string $url): bool
    {
        $url = filter_var($url, FILTER_VALIDATE_URL);
        if (!$url) {
            return false;
        }

        $parts = parse_url($url);

        # missing or invalid scheme
        if (!array_key_exists('scheme', $parts) || !in_array(strtolower($parts['scheme']), ['http', 'https'])) {
            return false;
        }

        # has user, pass, or fragment; not allowed
        if (array_key_exists('user', $parts) || array_key_exists('pass', $parts) || array_key_exists('fragment', $parts)) {
            return false;
        }

        # path has single-dot or double-dot segments; not allowed
        if (array_key_exists('path', $parts)) {
            $paths = explode('/', $parts['path']);
            if (array_intersect($paths, ['.', '..'])) {
                return false;
            }
        }

        # only allow ipv4/ipv6 if loopback
        $host = trim($parts['host'], '[]');
        $ip = filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6);
        $allowed = [
            '127.0.0.1',
            '0000:0000:0000:0000:0000:0000:0000:0001',
            '::1',
        ];

        if ($ip && !in_array($ip, $allowed)) {
            return false;
        }

        return true;
    }

    /**
     * Reserved for future use with Ticketing
     *
     * @see https://indieauth.spec.indieweb.org/#indieauth-server-metadata
     */
    public static function isIssuerValid(
        string $issuer,
        string $metadata_endpoint
    ): bool {
        if (!static::isClientIdValid($issuer)) {
            return false;
        }

        $issuer = static::canonizeUrl($issuer);
        $metadata_endpoint = static::canonizeUrl($metadata_endpoint);
        $parts = parse_url($issuer);

        if (!array_key_exists('scheme', $parts) || $parts['scheme'] != 'https') {
            return false;
        }

        if (array_key_exists('query', $parts) || array_key_exists('fragment', $parts)) {
            return false;
        }

        if (strpos($metadata_endpoint, $issuer) !== 0) {
            return false;
        }

        return true;
    }

    /**
     * @see https://indieauth.spec.indieweb.org/#url-canonicalization
     */
    public static function canonizeUrl(string $url): string
    {
        $parts = parse_url($url);
        $output = '';

        if (array_key_exists('scheme', $parts)) {
            $output .= strtolower($parts['scheme']) . '://';
        }

        if (array_key_exists('host', $parts)) {
            $output .= strtolower($parts['host']);
        }

        if (array_key_exists('port', $parts)) {
            $output .= ':' . $parts['port'];
        }

        $path = '/';
        if (array_key_exists('path', $parts)) {
            $path = $parts['path'];
        }
        $output .= $path;

        if (array_key_exists('query', $parts)) {
            $output .= '?' . $parts['query'];
        }

        return $output;
    }

    /**
     * URLs should be canonized before calling this function
     */
    public static function isRedirectUriAllowed(
        string $redirect_uri,
        string $client_id,
        array $registered_redirects = []
    ): bool {
        $parts_redirect_uri = parse_url($redirect_uri);
        $parts_client_id = parse_url($client_id);

        if (
            $parts_redirect_uri['scheme'] !== $parts_client_id['scheme']
            || $parts_redirect_uri['host'] !== $parts_client_id['host']
            || ($parts_redirect_uri['port'] ?? 0) !== ($parts_client_id['port'] ?? 0)
        ) {

            if (!in_array($redirect_uri, $registered_redirects)) {
                return false;
            }
        }

        return true;
    }

    public static function buildUrlWithQueryString(string $url, array $queryParams): string
    {
        $delimiter = '?';
        if (parse_url($url, PHP_URL_QUERY)) {
            $delimiter = '&';
        }

        return $url . $delimiter . http_build_query($queryParams);
    }

    public static function isCodeVerifierValid(string $code_verifier, string $code_challenge)
    {
        $verifier = self::base64UrlEncode(hash('sha256', $code_verifier, true));
        return (strcmp($code_challenge, $verifier) === 0);
    }

    public static function base64UrlEncode(string $input): string
    {
        return rtrim(strtr(base64_encode($input), '+/', '-_'), '=');
    }

    /**
     * Perform a HEAD request and return an array of headers
     * If $requested_headers is provided, only return those headers.
     * For example, `$requested_headers = ['link']` will return
     * only the Link: headers
     */
    private static function fetchHead(
        string $url,
        array $requested_headers = []
    ): ?array {
        $http = new WireHttp();

        $response = $http->status($url);
        if (!$response) {
            return null;
        }

        $http_headers = $http->getResponseHeaderValues('', true);

        if ($requested_headers) {
            $http_headers = array_intersect_key(
                $http_headers,
                array_fill_keys($requested_headers, [])
            );

            if (!$http_headers) {
                return null;
            }
        }

        return $http_headers;
    }

    /**
     * Fetch the content of a URL
     */
    private static function fetchBody(string $url): string
    {
        $http = new WireHttp();
        $content = $http->get($url);

        if (!$content) {
            return '';
        }

        return $content;
    }

    private static function hasContentType(
        string $expected,
        array $content_types
    ) {
        foreach ($content_types as $content_type) {
            if (stripos($content_type, $expected) !== false) {
                return true;
            }
        }

        return false;
    }
}

