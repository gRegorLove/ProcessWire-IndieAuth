<?php
/**
 * Template for IndieAuth authentication
 *
 * @author gRegor Morrill, https://gregorlove.com
 * @copyright 2021 gRegor Morrill
 * @license https://opensource.org/licenses/MIT MIT
 */

declare(strict_types=1);

namespace ProcessWire;
?>

<form method="post" action="<?=$this->page->url?>authorization">

    <div class="uk-card uk-card-default uk-background-muted uk-card-body">

        <div class="uk-flex">
            <h2 class="uk-margin-remove"> <?=$logo?> <a href="<?=$url?>"><?=$name?></a> is asking you to sign in. </h2>
        </div>

        <p> Select <b>Continue</b> to sign in as <?=$this->urls->httpRoot?>. Otherwise, select <b>Cancel</b>. </p>
        <p class="uk-text-small"> You will be redirected to: <?=$redirect_uri?>. </p>

        <p> <input type="submit" value="Continue" class="uk-button uk-button-primary"> <a href="<?=$this->page->url?>cancel" class="uk-button uk-button-danger uk-margin-left">Cancel</a> </p>

        <input type="hidden" name="scopes[]" value="">
    </div>

</form>

