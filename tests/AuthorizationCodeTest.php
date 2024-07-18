<?php

declare(strict_types=1);

namespace IndieAuth\Tests;

use IndieAuth\AuthorizationCode;
use PHPUnit\Framework\TestCase;

class AuthorizationCodeTest extends TestCase
{
    public function testGenerate()
    {
        $client_id = 'https://example.com/';
        $redirect_uri = 'https://example.com/redirect';
        $scope = 'read';

    	$AuthorizationCode = AuthorizationCode::fromRequest([
    		'client_id' => $client_id,
    		'redirect_uri' => $redirect_uri,
            'scope' => $scope,
    	], 'secret');

        # code_id is 8 bytes, returned in hex, so expect 16 bytes
        $this->assertEquals(16, mb_strlen($AuthorizationCode->code_id));

        $this->assertArrayHasKey('client_id', $AuthorizationCode->request);
        $this->assertArrayHasKey('redirect_uri', $AuthorizationCode->request);
        $this->assertArrayHasKey('scope', $AuthorizationCode->request);

        $this->assertEquals($client_id, $AuthorizationCode->request['client_id']);
        $this->assertEquals($redirect_uri, $AuthorizationCode->request['redirect_uri']);
        $this->assertEquals($scope, $AuthorizationCode->request['scope']);

        $this->assertNotEmpty($AuthorizationCode->value);
    }

    public function testDecode()
    {
        $client_id = 'https://another.example.com/';
        $redirect_uri = 'https://another.example.com/redirect';
        $scope = 'read';
        $secret = 'secret2';

        $AuthorizationCode = AuthorizationCode::fromRequest([
            'client_id' => $client_id,
            'redirect_uri' => $redirect_uri,
            'scope' => $scope,
        ], $secret);

        $decoded = AuthorizationCode::decode(
            $AuthorizationCode->value,
            $secret);

        # code_id is 8 bytes, returned in hex, so expect 16 bytes
        $this->assertEquals(16, mb_strlen($decoded['id']));

        $this->assertArrayHasKey('client_id', $decoded);
        $this->assertArrayHasKey('redirect_uri', $decoded);
        $this->assertArrayHasKey('scope', $decoded);

        $this->assertEquals($client_id, $decoded['client_id']);
        $this->assertEquals($redirect_uri, $decoded['redirect_uri']);
        $this->assertEquals($scope, $decoded['scope']);
    }
}

