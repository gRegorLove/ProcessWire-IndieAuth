<?php

declare(strict_types=1);

namespace IndieAuth\Tests;

use IndieAuth\Server;
use PHPUnit\Framework\TestCase;

class ServerTest extends TestCase
{
    public function testHasScheme(): void
    {
        $this->assertFalse(
            Server::isClientIdValid('example.com')
        );
    }

    public function testSchemeHttp(): void
    {
        $this->assertTrue(
            Server::isClientIdValid('http://example.com')
        );
    }

    public function testSchemeHttps(): void
    {
        $this->assertTrue(
            Server::isClientIdValid('https://example.com')
        );
    }

    public function testSchemeOther(): void
    {
        $this->assertFalse(
            Server::isClientIdValid('ftp://example.com')
        );
    }

    public function testUser(): void
    {
        $this->assertFalse(
            Server::isClientIdValid('http://user@example.com')
        );
    }

    public function testUserPass(): void
    {
        $this->assertFalse(
            Server::isClientIdValid('https://user:pass@example.com')
        );
    }

    public function testDotPath(): void
    {
        $this->assertFalse(
            Server::isClientIdValid('https://example.com/./')
        );
    }

    public function testDoubleDotPath(): void
    {
        $this->assertFalse(
            Server::isClientIdValid('https://example.com/../')
        );
    }

    public function testFragment(): void
    {
        $this->assertFalse(
            Server::isClientIdValid('https://example.com/#id')
        );
    }

    public function testIpv4(): void
    {
        $this->assertFalse(
            Server::isClientIdValid('https://1.1.1.1')
        );
    }

    public function testIpv6(): void
    {
        $this->assertFalse(
            Server::isClientIdValid('https://[2606:4700:4700::1111]')
        );
    }

    public function testIpv4Loopback(): void
    {
        $this->assertTrue(
            Server::isClientIdValid('https://127.0.0.1')
        );
    }

    public function testIpv6Loopback(): void
    {
        $this->assertTrue(
            Server::isClientIdValid('https://[0000:0000:0000:0000:0000:0000:0000:0001]')
        );
    }

    public function testCanonizedPath(): void
    {
        $this->assertEquals(
            Server::canonizeUrl('https://example.com'),
            'https://example.com/'
        );
    }

    public function testCanonizedSchemeHost(): void
    {
        $this->assertEquals(
            Server::canonizeUrl('Https://Example.Com/Path'),
            'https://example.com/Path'
        );
    }

    public function testRedirectUriSchemeMismatch(): void
    {
        $this->assertFalse(
            Server::isRedirectUriAllowed(
                'http://client.example/callback',
                'https://client.example'
            )
        );
    }

    public function testRedirectUriHostMismatch(): void
    {
        $this->assertFalse(
            Server::isRedirectUriAllowed(
                'https://client.example/redirect',
                'https://example.com'
            )
        );
    }

    public function testRedirectUriPortMismatch(): void
    {
        $this->assertFalse(
            Server::isRedirectUriAllowed(
                'https://client.example/redirect',
                'https://client.example:2083'
            )
        );
    }

    public function testBase64UrlEncode(): void
    {
        $this->assertEquals( Server::base64UrlEncode(''), '' );
        $this->assertEquals( Server::base64UrlEncode('f'), 'Zg' );
        $this->assertEquals( Server::base64UrlEncode('fo'), 'Zm8' );
        $this->assertEquals( Server::base64UrlEncode('foo'), 'Zm9v' );
        $this->assertEquals( Server::base64UrlEncode('foob'), 'Zm9vYg' );
        $this->assertEquals( Server::base64UrlEncode('fooba'), 'Zm9vYmE' );
        $this->assertEquals( Server::base64UrlEncode('foobar'), 'Zm9vYmFy' );

        $data = hex2bin('8af1d0b4675acfd26e294f83db290d6b');
        $this->assertEquals( Server::base64UrlEncode($data), 'ivHQtGdaz9JuKU-D2ykNaw' );

        $data = hex2bin('b8147f7d168631bbacbf57cc746a580d');
        $this->assertEquals( Server::base64UrlEncode($data), 'uBR_fRaGMbusv1fMdGpYDQ' );
    }

    public function testCodeVerifierValid(): void
    {
        $code_verifier = 'foobar';
        $code_challenge = Server::base64UrlEncode(hash('sha256', $code_verifier, true));
        $this->assertTrue( Server::isCodeVerifierValid($code_verifier, $code_challenge) );
    }

    public function testIssuerHttps(): void
    {
        $this->assertFalse(
            Server::isIssuerValid(
                'http://example.com',
                'http://example.com/metadata-endpoint'
            )
        );
        $this->assertTrue(
            Server::isIssuerValid(
                'https://example.com',
                'https://example.com/metadata-endpoint'
            )
        );
    }

    public function testIssuerNoQuery(): void
    {
        $this->assertFalse(
            Server::isIssuerValid(
                'https://example.com/?issuer=1',
                'https://example.com/metadata-endpoint'
            )
        );
    }

    public function testIssuerNoFragment(): void
    {
        $this->assertFalse(
            Server::isIssuerValid(
                'https://example.com/#issuer',
                'https://example.com/metadata-endpoint'
            )
        );
    }

    public function testIssuerPrefix(): void
    {
        $this->assertTrue(
            Server::isIssuerValid(
                'https://example.com/',
                'https://example.com/metadata/endpoint'
            )
        );
    }
}

