<?php

declare(strict_types=1);

namespace IndieAuth\Tests;

use PHPUnit\Framework\TestCase;
use IndieAuth\Server;

class ClientIdTest extends TestCase
{
    public function test_has_scheme()
    {
        $this->assertFalse(
            Server::isClientIdValid('example.com')
        );
    }

    public function test_scheme_http()
    {
        $this->assertTrue(
            Server::isClientIdValid('http://example.com')
        );
    }

    public function test_scheme_https()
    {
        $this->assertTrue(
            Server::isClientIdValid('https://example.com')
        );
    }

    public function test_scheme_other()
    {
        $this->assertFalse(
            Server::isClientIdValid('ftp://example.com')
        );
    }

    public function test_user()
    {
        $this->assertFalse(
            Server::isClientIdValid('http://user@example.com')
        );
    }

    public function test_user_pass()
    {
        $this->assertFalse(
            Server::isClientIdValid('https://user:pass@example.com')
        );
    }

    public function test_dot_path()
    {
        $this->assertFalse(
            Server::isClientIdValid('https://example.com/./')
        );
    }

    public function test_double_dot_path()
    {
        $this->assertFalse(
            Server::isClientIdValid('https://example.com/../')
        );
    }

    public function test_fragment()
    {
        $this->assertFalse(
            Server::isClientIdValid('https://example.com/#id')
        );
    }

    public function test_ipv4()
    {
        $this->assertFalse(
            Server::isClientIdValid('https://1.1.1.1')
        );
    }

    public function test_ipv6()
    {
        $this->assertFalse(
            Server::isClientIdValid('https://[2606:4700:4700::1111]')
        );
    }

    public function test_ipv4_loopback()
    {
        $this->assertTrue(
            Server::isClientIdValid('https://127.0.0.1')
        );
    }

    public function test_ipv6_loopback()
    {
        $this->assertTrue(
            Server::isClientIdValid('https://[0000:0000:0000:0000:0000:0000:0000:0001]')
        );
    }

    public function test_canonized_path()
    {
        $this->assertEquals(
            Server::canonizeUrl('https://example.com'),
            'https://example.com/'
        );
    }

    public function test_canonized_scheme_host()
    {
        $this->assertEquals(
            Server::canonizeUrl('Https://Example.Com/Path'),
            'https://example.com/Path'
        );
    }

    public function test_redirect_uri_scheme_mismatch()
    {
        $this->assertFalse(
            Server::isRedirectUriAllowed(
                'http://client.example/callback',
                'https://client.example'
            )
        );
    }

    public function test_redirect_uri_host_mismatch()
    {
        $this->assertFalse(
            Server::isRedirectUriAllowed(
                'https://client.example/redirect',
                'https://example.com'
            )
        );
    }

    public function test_redirect_uri_port_mismatch()
    {
        $this->assertFalse(
            Server::isRedirectUriAllowed(
                'https://client.example/redirect',
                'https://client.example:2083'
            )
        );
    }

}

