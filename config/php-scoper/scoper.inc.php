<?php

declare(strict_types = 1);

// scoper.inc.php

use Isolated\Symfony\Component\Finder\Finder;

return [
    'prefix'  => 'IndieAuth\\Libs',
    'output-dir' => 'scoped-libs',
    'finders' => [
        Finder::create()->files()->in( 'vendor/mf2/mf2' )->name( [ '*.php', 'LICENSE', 'composer.json' ] ),
        Finder::create()->files()->in( 'vendor/barnabywalters/mf-cleaner' )->name( [ '*.php', 'LICENSE', 'composer.json' ] ),
        Finder::create()->files()->in( 'vendor/firebase/php-jwt' )->name( [ '*.php', 'LICENSE', 'composer.json' ] ),
    ],
];

