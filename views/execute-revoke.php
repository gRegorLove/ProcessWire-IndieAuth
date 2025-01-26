<?php
/**
 * Template for IndieAuth token revoke (admin)
 *
 * @author gRegor Morrill, https://gregorlove.com
 * @copyright 2021 gRegor Morrill
 * @license https://opensource.org/licenses/MIT MIT
 */

declare(strict_types=1);

namespace ProcessWire;

$display_client_id = '';
if ($client_id != $client_uri) {
    $display_client_id .= PHP_EOL . sprintf('<br> <small>Client ID: %s</small>', $client_id);
}

?>

<p> <b>Are you sure you want to revoke this access token?</b> </p>

<p> Client:<br> <a href="<?=$client_uri;?>" target="_blank" title="Link will open in a new window" rel="noopener"><?=$client_name;?></a> <?=$display_client_id?> </p>
<p> Token Ending With:<br> <?=$ending;?> </p>
<p> Scope:<br> <?=$scope;?> </p>
<p> Issued:<br> <?=$issued_at;?> </p>

<form method="post" action="<?=$this->page->url;?>revoke">
    <input type="hidden" name="id" value="<?=$id;?>">
    <input type="submit" value="Revoke Token" class="ui-button">
    <a href="<?=$this->page->url;?>" class="ui-button ui-priority-secondary">Cancel</a>
</form>

