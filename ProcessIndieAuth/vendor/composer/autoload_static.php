<?php

// autoload_static.php @generated by Composer

namespace Composer\Autoload;

class ComposerStaticInita3f135fc7ff74331d581d4d9b4d9ea9c
{
    public static $files = array (
        '75114ff88d0fe0413bbfd961d51cb0e3' => __DIR__ . '/..' . '/barnabywalters/mf-cleaner/src/BarnabyWalters/Mf2/Functions.php',
        '757772e28a0943a9afe83def8db95bdf' => __DIR__ . '/..' . '/mf2/mf2/Mf2/Parser.php',
    );

    public static $prefixLengthsPsr4 = array (
        'I' => 
        array (
            'IndieAuth\\' => 10,
        ),
        'F' => 
        array (
            'Firebase\\JWT\\' => 13,
        ),
    );

    public static $prefixDirsPsr4 = array (
        'IndieAuth\\' => 
        array (
            0 => __DIR__ . '/../..' . '/src/IndieAuth',
        ),
        'Firebase\\JWT\\' => 
        array (
            0 => __DIR__ . '/..' . '/firebase/php-jwt/src',
        ),
    );

    public static $classMap = array (
        'Composer\\InstalledVersions' => __DIR__ . '/..' . '/composer/InstalledVersions.php',
    );

    public static function getInitializer(ClassLoader $loader)
    {
        return \Closure::bind(function () use ($loader) {
            $loader->prefixLengthsPsr4 = ComposerStaticInita3f135fc7ff74331d581d4d9b4d9ea9c::$prefixLengthsPsr4;
            $loader->prefixDirsPsr4 = ComposerStaticInita3f135fc7ff74331d581d4d9b4d9ea9c::$prefixDirsPsr4;
            $loader->classMap = ComposerStaticInita3f135fc7ff74331d581d4d9b4d9ea9c::$classMap;

        }, null, ClassLoader::class);
    }
}
