<?php
/**
 * Template for IndieAuth token list (admin)
 *
 * @author gRegor Morrill, https://gregorlove.com
 * @copyright 2021 gRegor Morrill
 * @license https://opensource.org/licenses/MIT MIT
 */

if ($table) {
	echo '<p> You have granted access to the following applications. </p>';
	echo $table->render();
	echo $results->renderPager();
} else {
	echo '<p> There are no access tokens currently. </p>';
}

