<?php

// autoload_static.php @generated by Composer

namespace Composer\Autoload;

class ComposerStaticInitfebeb09cb9045d91c5981c163cb3421e
{
    public static $files = array (
        'eb9c22d6e1a07d2b2bf99fa9c6b4e857' => __DIR__ . '/../..' . '/scoped-libs/mf2/mf2/Mf2/Parser.php',
        'e543e19c14ae0c8c139d55822040dede' => __DIR__ . '/../..' . '/scoped-libs/barnabywalters/mf-cleaner/src/functions.php',
    );

    public static $prefixLengthsPsr4 = array (
        'I' => 
        array (
            'IndieAuth\\' => 10,
        ),
    );

    public static $prefixDirsPsr4 = array (
        'IndieAuth\\' => 
        array (
            0 => __DIR__ . '/../..' . '/src/IndieAuth',
        ),
    );

    public static $classMap = array (
        'Composer\\InstalledVersions' => __DIR__ . '/..' . '/composer/InstalledVersions.php',
        'IndieAuth\\Libs\\BarnabyWalters\\Mf2\\CleanerTest' => __DIR__ . '/../..' . '/scoped-libs/barnabywalters/mf-cleaner/tests/CleanerTest.php',
        'IndieAuth\\Libs\\Firebase\\JWT\\BeforeValidException' => __DIR__ . '/../..' . '/scoped-libs/firebase/php-jwt/src/BeforeValidException.php',
        'IndieAuth\\Libs\\Firebase\\JWT\\CachedKeySet' => __DIR__ . '/../..' . '/scoped-libs/firebase/php-jwt/src/CachedKeySet.php',
        'IndieAuth\\Libs\\Firebase\\JWT\\ExpiredException' => __DIR__ . '/../..' . '/scoped-libs/firebase/php-jwt/src/ExpiredException.php',
        'IndieAuth\\Libs\\Firebase\\JWT\\JWK' => __DIR__ . '/../..' . '/scoped-libs/firebase/php-jwt/src/JWK.php',
        'IndieAuth\\Libs\\Firebase\\JWT\\JWT' => __DIR__ . '/../..' . '/scoped-libs/firebase/php-jwt/src/JWT.php',
        'IndieAuth\\Libs\\Firebase\\JWT\\JWTExceptionWithPayloadInterface' => __DIR__ . '/../..' . '/scoped-libs/firebase/php-jwt/src/JWTExceptionWithPayloadInterface.php',
        'IndieAuth\\Libs\\Firebase\\JWT\\Key' => __DIR__ . '/../..' . '/scoped-libs/firebase/php-jwt/src/Key.php',
        'IndieAuth\\Libs\\Firebase\\JWT\\SignatureInvalidException' => __DIR__ . '/../..' . '/scoped-libs/firebase/php-jwt/src/SignatureInvalidException.php',
        'IndieAuth\\Libs\\Mf2\\Parser' => __DIR__ . '/../..' . '/scoped-libs/mf2/mf2/Mf2/Parser.php',
        'IndieAuth\\Libs\\Mf2\\Parser\\Test\\ClassicMicroformatsTest' => __DIR__ . '/../..' . '/scoped-libs/mf2/mf2/tests/Mf2/ClassicMicroformatsTest.php',
        'IndieAuth\\Libs\\Mf2\\Parser\\Test\\CombinedMicroformatsTest' => __DIR__ . '/../..' . '/scoped-libs/mf2/mf2/tests/Mf2/CombinedMicroformatsTest.php',
        'IndieAuth\\Libs\\Mf2\\Parser\\Test\\MicroformatsTestSuiteTest' => __DIR__ . '/../..' . '/scoped-libs/mf2/mf2/tests/Mf2/MicroformatsTestSuiteTest.php',
        'IndieAuth\\Libs\\Mf2\\Parser\\Test\\MicroformatsWikiExamplesTest' => __DIR__ . '/../..' . '/scoped-libs/mf2/mf2/tests/Mf2/MicroformatsWikiExamplesTest.php',
        'IndieAuth\\Libs\\Mf2\\Parser\\Test\\ParseDTTest' => __DIR__ . '/../..' . '/scoped-libs/mf2/mf2/tests/Mf2/ParseDTTest.php',
        'IndieAuth\\Libs\\Mf2\\Parser\\Test\\ParseHtmlIdTest' => __DIR__ . '/../..' . '/scoped-libs/mf2/mf2/tests/Mf2/ParseHtmlIdTest.php',
        'IndieAuth\\Libs\\Mf2\\Parser\\Test\\ParseImpliedTest' => __DIR__ . '/../..' . '/scoped-libs/mf2/mf2/tests/Mf2/ParseImpliedTest.php',
        'IndieAuth\\Libs\\Mf2\\Parser\\Test\\ParseLanguageTest' => __DIR__ . '/../..' . '/scoped-libs/mf2/mf2/tests/Mf2/ParseLanguageTest.php',
        'IndieAuth\\Libs\\Mf2\\Parser\\Test\\ParsePTest' => __DIR__ . '/../..' . '/scoped-libs/mf2/mf2/tests/Mf2/ParsePTest.php',
        'IndieAuth\\Libs\\Mf2\\Parser\\Test\\ParseUTest' => __DIR__ . '/../..' . '/scoped-libs/mf2/mf2/tests/Mf2/ParseUTest.php',
        'IndieAuth\\Libs\\Mf2\\Parser\\Test\\ParseValueClassTitleTest' => __DIR__ . '/../..' . '/scoped-libs/mf2/mf2/tests/Mf2/ParseValueClassTitleTest.php',
        'IndieAuth\\Libs\\Mf2\\Parser\\Test\\ParserTest' => __DIR__ . '/../..' . '/scoped-libs/mf2/mf2/tests/Mf2/ParserTest.php',
        'IndieAuth\\Libs\\Mf2\\Parser\\Test\\PlainTextTest' => __DIR__ . '/../..' . '/scoped-libs/mf2/mf2/tests/Mf2/PlainTextTest.php',
        'IndieAuth\\Libs\\Mf2\\Parser\\Test\\RelTest' => __DIR__ . '/../..' . '/scoped-libs/mf2/mf2/tests/Mf2/RelTest.php',
        'IndieAuth\\Libs\\Mf2\\Parser\\Test\\TestSuiteParser' => __DIR__ . '/../..' . '/scoped-libs/mf2/mf2/tests/Mf2/MicroformatsTestSuiteTest.php',
        'IndieAuth\\Libs\\Mf2\\Parser\\Test\\UrlTest' => __DIR__ . '/../..' . '/scoped-libs/mf2/mf2/tests/Mf2/URLTest.php',
    );

    public static function getInitializer(ClassLoader $loader)
    {
        return \Closure::bind(function () use ($loader) {
            $loader->prefixLengthsPsr4 = ComposerStaticInitfebeb09cb9045d91c5981c163cb3421e::$prefixLengthsPsr4;
            $loader->prefixDirsPsr4 = ComposerStaticInitfebeb09cb9045d91c5981c163cb3421e::$prefixDirsPsr4;
            $loader->classMap = ComposerStaticInitfebeb09cb9045d91c5981c163cb3421e::$classMap;

        }, null, ClassLoader::class);
    }
}
