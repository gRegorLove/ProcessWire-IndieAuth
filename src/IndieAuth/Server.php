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

final class Server 
{
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
}

