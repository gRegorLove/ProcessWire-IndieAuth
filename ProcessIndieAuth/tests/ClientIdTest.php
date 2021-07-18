<?php

declare(strict_types=1);

namespace ProcessWire;

use PHPUnit\Framework\TestCase;

class ClientIdTest extends TestCase
{
	private $module;

	protected function setUp(): void
	{
		$this->module = wire('modules')->get('IndieAuth');
	}

	public function test_has_scheme()
	{
		$this->assertFalse(
			$this->module->is_client_id_valid('example.com')
		);
	}

	public function test_scheme_http()
	{
		$this->assertTrue(
			$this->module->is_client_id_valid('http://example.com')
		);
	}

	public function test_scheme_https()
	{
		$this->assertTrue(
			$this->module->is_client_id_valid('https://example.com')
		);
	}

	public function test_scheme_other()
	{
		$this->assertFalse(
			$this->module->is_client_id_valid('ftp://example.com')
		);
	}

	public function test_user()
	{
		$this->assertFalse(
			$this->module->is_client_id_valid('http://user@example.com')
		);
	}

	public function test_user_pass()
	{
		$this->assertFalse(
			$this->module->is_client_id_valid('https://user:pass@example.com')
		);
	}

	public function test_dot_path()
	{
		$this->assertFalse(
			$this->module->is_client_id_valid('https://example.com/./')
		);
	}

	public function test_double_dot_path()
	{
		$this->assertFalse(
			$this->module->is_client_id_valid('https://example.com/../')
		);
	}

	public function test_fragment()
	{
		$this->assertFalse(
			$this->module->is_client_id_valid('https://example.com/#id')
		);
	}

	public function test_ipv4()
	{
		$this->assertFalse(
			$this->module->is_client_id_valid('https://1.1.1.1')
		);
	}

	public function test_ipv6()
	{
		$this->assertFalse(
			$this->module->is_client_id_valid('https://[2606:4700:4700::1111]')
		);
	}

	public function test_ipv4_loopback()
	{
		$this->assertTrue(
			$this->module->is_client_id_valid('https://127.0.0.1')
		);
	}

	public function test_ipv6_loopback()
	{
		$this->assertTrue(
			$this->module->is_client_id_valid('https://[0000:0000:0000:0000:0000:0000:0000:0001]')
		);
	}

	public function test_canonized_path()
	{
		$this->assertEquals(
			$this->module->canonize_url('https://example.com'),
			'https://example.com/'
		);
	}

	public function test_canonized_scheme_host()
	{
		$this->assertEquals(
			$this->module->canonize_url('Https://Example.Com/Path'),
			'https://example.com/Path'
		);
	}

	public function test_redirect_uri_scheme_mismatch()
	{
		$this->assertFalse(
			$this->module->is_redirect_uri_whitelisted(
				'http://client.example/callback',
				'https://client.example'
			)
		);
	}

	public function test_redirect_uri_host_mismatch()
	{
		$this->assertFalse(
			$this->module->is_redirect_uri_whitelisted(
				'https://client.example/redirect',
				'https://example.com'
			)
		);
	}

	public function test_redirect_uri_port_mismatch()
	{
		$this->assertFalse(
			$this->module->is_redirect_uri_whitelisted(
				'https://client.example/redirect',
				'https://client.example:2083'
			)
		);
	}

}

