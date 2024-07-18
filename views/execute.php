<?php
/**
 * Template for IndieAuth token list (admin)
 *
 * @author gRegor Morrill, https://gregorlove.com
 * @copyright 2021 gRegor Morrill
 * @license https://opensource.org/licenses/MIT MIT
 */

declare(strict_types=1);

namespace ProcessWire;

if ($table):
?>

    <p> You have granted access to the following applications. </p>
    <p> An <b>R</b> in the expiration column means the access has expired, but the application can still refresh the access until the listed date. </p>
    <?=$table->render();?>
    <?=$results->renderPager();?>

<?php else: ?>

    <p> There are no access tokens currently. </p>

<?php endif; ?>

<details>
    <summary>Advanced:</summary>
    <ul>
        <li> <a href="<?=$this->page->url?>clients">Manage Client Credentials</a> </li>
        <li> <a href="<?=$this->page->url?>add-token">Developers: Manually Add a Token</a> </li>
    </ul>
</details>

