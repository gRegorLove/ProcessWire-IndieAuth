<?php
/**
 * This class creates, encodes, and decodes authorization codes
 * @see https://indieauth.spec.indieweb.org/
 *
 * @author gRegor Morrill, https://gregorlove.com
 * @copyright 2021 gRegor Morrill
 * @license https://opensource.org/licenses/MIT MIT
 */

declare(strict_types=1);

namespace IndieAuth;

use Exception;
use IndieAuth\Libs\Firebase\JWT\{
    JWT,
    Key
};
use function ProcessWire\wire;

final class AuthorizationCode
{
    private $code_id;
    private $request = [];
    private $value;

    public function __construct(string $code_id, array $request, ?string $value = null)
    {
        $this->code_id = $code_id;
        $this->request = $request;
        $this->value = $value;
    }

    public function __get(string $property)
    {
        if (property_exists($this, $property)) {
            return $this->$property;
        }

        return null;
    }

    /**
     * Create a new AuthorizationCode based on requested parameters
     */
    public static function fromRequest(array $request, string $secret): AuthorizationCode
    {
        $object = new self(
            bin2hex(random_bytes(8)),
            $request
        );
        $object->generate($secret);
        return $object;
    }

    private function generate(string $secret): void
    {
        $data = [
            'id' => $this->code_id,
            'me' => wire('urls')->httpRoot,
            'client_id' => $this->request['client_id'],
            'redirect_uri' => $this->request['redirect_uri'],
            'iat' => time(),
            'exp' => strtotime('+5 minutes'),
            'client_name' => $this->request['client_name'] ?? '',
            'client_logo' => $this->request['client_logo'] ?? '',
        ];

        if (array_key_exists('scope', $this->request)) {
            $data['scope'] = $this->request['scope'];
        }

        if ($token_lifetime = wire('session')->getFor('IndieAuth', 'token_lifetime')) {
            $data['token_lifetime'] = $token_lifetime;
        }

        $this->value = JWT::encode($data, $secret, 'HS256');
    }

    public static function decode(string $code, string $secret): ?array
    {
        try {
            JWT::$leeway = 30;
            $decoded = (array) JWT::decode($code, new Key($secret, 'HS256'));
            return $decoded;
        } catch (Exception $e) {
            return null;
        }
    }
}

