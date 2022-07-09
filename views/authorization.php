<?php
/**
 * Template for IndieAuth authorization
 *
 * @author gRegor Morrill, https://gregorlove.com
 * @copyright 2021 gRegor Morrill
 * @license https://opensource.org/licenses/MIT MIT
 */

declare(strict_types=1);

namespace ProcessWire;

$display_scopes = PHP_EOL . '<ul class="uk-list">';
foreach ($scopes as $scope) {
    $display_scopes .= PHP_EOL . sprintf('<li> <label><input type="checkbox" name="scopes[]" value="%s" checked> %1$s</label> </li>',
        $scope
    );
}
$display_scopes .= PHP_EOL . '</ul>';
?>

<form method="post" action="<?=$this->page->url?>authorization">

    <div class="uk-card uk-card-default uk-background-muted uk-card-body">

        <div class="uk-flex">
            <h2 class="uk-margin-remove"> <?=$logo?> <a href="<?=$url?>"><?=$name?></a> is asking to access your site. </h2>
        </div>

        <div class="uk-grid uk-child-width-expand">
            <div>
                <h3> Scope </h3>
                <p> The app is requesting the following scopes: </p>
                <?=$display_scopes?>

                <p class="uk-text-small"> <a href="https://indieweb.org/scope" rel="noopener" target="_blank">Learn more about scopes</a> </p>
            </div>
            <div>
                <h3> Expiration </h3>
                <p> The app will be authorized for: <?=$token_lifetime?>. </p>

                <input type="hidden" name="expiration" value="normal">
                <p> <label><input type="checkbox" name="expiration" value="none"> I would like to authorize this app with no expiration</label> </p>

                <p class="uk-text-small"> You can revoke an app’s access in the admin at <em>any</em> time. </p>
            </div>
        </div>

        <p> Select <b>Allow</b> to approve the request and sign in as <?=$this->urls->httpRoot?>. Otherwise, select <b>Cancel</b>. </p>
        <p class="uk-text-small"> You will be redirected to: <?=$redirect_uri?>. </p>

        <p> <input type="submit" value="Allow" class="uk-button uk-button-primary"> <a href="<?=$this->page->url?>cancel" class="uk-button uk-button-danger uk-margin-left">Cancel</a> </p>
    </div>

</form>

