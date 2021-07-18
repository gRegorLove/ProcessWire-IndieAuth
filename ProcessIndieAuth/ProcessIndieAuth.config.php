<?php
/**
 * Module configuration
 *
 * @author gRegor Morrill, https://gregorlove.com
 * @copyright 2021 gRegor Morrill
 * @license https://opensource.org/licenses/MIT MIT
 */

declare(strict_types=1);

namespace ProcessWire;

$config = [
    'token_lifetime' => [
        'type' => 'text',
        'label' => 'Default access token lifetime',
        'description' => 'In seconds',
        'value' => 1209600,
        'required' => true,
    ],
    'token_secret' => [
        'type' => 'hidden',
    ],
];

