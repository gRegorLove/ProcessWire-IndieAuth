<?php

	if ( $input->get->code )
	{
		# get the IndieAuth module
		$IndieAuth = $modules->get('IndieAuth');

		# verify the code indieauth.com sent back
		$response = $IndieAuth->verifyCode($input->get->code);

		# if: error verifying code; display message and halt
		if ( $response['result'] === FALSE )
		{
			echo $response['message']; exit;
		}

		# attempt to log the user in to ProcessWire (optional)
		$IndieAuth->authenticateByDomain();

		# redirect to homepage
		$session->redirect('/', FALSE);
	}

	print <<< END
	<form action="https://indieauth.com/auth" method="get">
		<p> <label for="indie_auth_url">Web Address:</label> <input id="indie_auth_url" type="text" name="me" placeholder="yourdomain.com" /> <?p>
		<p><button type="submit">Sign In</button></p>
		<input type="hidden" name="client_id" value="https://{$config->httpHost}" />
		<input type="hidden" name="redirect_uri" value="{$page->httpUrl}" />
	</form>
END;

