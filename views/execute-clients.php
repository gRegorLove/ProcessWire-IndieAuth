<?php
/**
 * Template for IndieAuth clients list (admin)
 *
 * @author gRegor Morrill, https://gregorlove.com
 * @copyright 2023 gRegor Morrill
 * @license https://opensource.org/licenses/MIT MIT
 */

declare(strict_types=1);

namespace ProcessWire;

if ($table):
?>

    <p> <b>Advanced:</b> use this page if you need to set up <a href="https://www.oauth.com/oauth2-servers/access-tokens/client-credentials/" target="_blank" rel="noopener">Client Credentials</a> allowing a client to authenticate as itself instead of a user. </p>

    <p> You do not need to add anything here to use IndieAuth to sign in with your domain name. </p>

    <?=$table->render();?>
    <?=$results->renderPager();?>

<?php else: ?>

    <p> There are no clients currently. </p>

<?php endif; ?>

<a href="<?=$this->page->url?>add-client" class="ui-button">Add Client</a>

