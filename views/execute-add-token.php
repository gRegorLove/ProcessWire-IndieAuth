<?php
/**
 * Template for IndieAuth add token (admin)
 *
 * @author gRegor Morrill, https://gregorlove.com
 * @copyright 2023 gRegor Morrill
 * @license https://opensource.org/licenses/MIT MIT
 */

declare(strict_types=1);

namespace ProcessWire;

?>

<p> <b>Advanced:</b> only use this tool if you need to manually add and test an access token. The un-encrypted access token will be displayed on the next page. </p>

<p> The access token will still encrypted in the database and cannot be retrieved later. </p>

<p> This should only be used by developers while debugging. </p>

<?=$form->render();?>

