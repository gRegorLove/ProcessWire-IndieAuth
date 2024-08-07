<?php

namespace IndieAuth\Libs\BarnabyWalters\Mf2;

use InvalidArgumentException;
use IndieAuth\Libs\PHPUnit\Framework\TestCase;
/**
 * CleanerTest
 *
 * @author barnabywalters
 * @internal
 */
class CleanerTest extends TestCase
{
    protected function mf($name, array $properties, $value = '')
    {
        if (\is_array($name)) {
            $type = $name;
        } else {
            $type = [$name];
        }
        foreach ($properties as $name => $arg) {
            if (\is_array($arg) and !isMicroformat($arg) and !isEmbeddedHtml($arg)) {
                $properties[$name] = $arg;
            } else {
                $properties[$name] = [$arg];
            }
        }
        return ['type' => $type, 'properties' => $properties, 'value' => $value];
    }
    public function testIsMicroformatReturnsFalseIfNotArray()
    {
        $this->assertFalse(isMicroformat(''));
    }
    public function testIsMicroformatReturnsFalseIfTypeMissing()
    {
        $this->assertFalse(isMicroformat(['properties' => []]));
    }
    public function testIsMicroformatReturnsFalseIfPropertiesMissing()
    {
        $this->assertFalse(isMicroformat(['type' => ['h-thing']]));
    }
    public function testIsMicroformatReturnsFalseIfHasNumericKeys()
    {
        $this->assertFalse(isMicroformat([[], 'thing' => []]));
    }
    public function testIsMicroformatReturnsTrueIfValueIsSet()
    {
        $this->assertTrue(isMicroformat(['type' => ['h-card'], 'properties' => [], 'value' => 'a string']));
    }
    public function testHasNumericKeysWorks()
    {
        $withNumericKeys = ['a', 'b', 'c'];
        $noNumericKeys = ['key' => 'value'];
        $this->assertTrue(hasNumericKeys($withNumericKeys));
        $this->assertFalse(hasNumericKeys($noNumericKeys));
    }
    public function testIsMicroformatCollectionChecksForItemsKey()
    {
        $this->assertTrue(isMicroformatCollection(['items' => []]));
        $this->assertFalse(isMicroformatCollection(['notItems' => []]));
    }
    public function testGetSummaryPassesIfSummaryPresent()
    {
        $mf = $this->mf('h-entry', ['summary' => 'Hello Summary']);
        $result = getSummary($mf);
        $this->assertEquals($mf['properties']['summary'][0], $result);
    }
    public function testGetSummaryUsesStrippedFirstCharactersOfContent()
    {
        $result = getSummary(['type' => ['h-entry'], 'properties' => ['content' => ['<p>Hello hello hello there indeed</p>']]]);
        $this->assertEquals('Hello hello hello t…', $result);
    }
    public function testGetPublishedPassesIfPublishedPresent()
    {
        $mf = $this->mf('h-entry', ['published' => '2013-12-06']);
        $result = getPublished($mf);
        $this->assertEquals(getPlaintext($mf, 'published'), $result);
    }
    public function testGetPublishedFallsBackToUpdated()
    {
        $mf = $this->mf('h-entry', ['updated' => '2013-12-06']);
        $result = getPublished($mf);
        $this->assertEquals(getPlaintext($mf, 'updated'), $result);
    }
    public function testGetPublishedReturnsNullIfValidDatetimeRequested()
    {
        $mf = $this->mf('h-entry', ['published' => 'werty']);
        $this->assertNull(getPublished($mf, \true));
        $mf = $this->mf('h-entry', ['published' => '2022-01-01 10:00:00']);
        $this->assertEquals('2022-01-01 10:00:00', getPublished($mf, \true));
    }
    public function testGetPublishedReturnsNullIfNoPotentialValueFound()
    {
        $mf = $this->mf('h-entry', []);
        $result = getPublished($mf);
        $this->assertNull($result);
    }
    public function testGetPublishedReturnsFallbackIfProvided()
    {
        $mf = $this->mf('h-entry', []);
        $this->assertEquals('fallback', getPublished($mf, \true, 'fallback'));
    }
    public function testGetUpdated()
    {
        $mf = $this->mf('h-entry', ['updated' => '2013-12-06']);
        $this->assertEquals('2013-12-06', getUpdated($mf));
    }
    public function testGetAuthorPassesIfAuthorPresent()
    {
        $mf = $this->mf('h-entry', ['author' => [$this->mf('h-card', ['name' => 'Me'])]]);
        $this->assertEquals('Me', getPlaintext(getAuthor($mf), 'name'));
    }
    public function testGetAuthorFindsSeparateHCardWithSameName()
    {
        $nonAuthorCard = $this->mf('h-card', ['name' => 'Someone Else', 'url' => 'http://example.org']);
        $card = $this->mf('h-card', ['name' => 'Me', 'url' => 'http://waterpigs.co.uk']);
        $entry = $this->mf('h-entry', ['name' => 'Entry', 'author' => 'Me']);
        $mfs = ['items' => [$nonAuthorCard, $card, $entry]];
        $result = getAuthor($entry, $mfs);
        $this->assertEquals('http://waterpigs.co.uk', getPlaintext($result, 'url'));
    }
    public function testGetAuthorFindsSeparateHCardWithSameDomain()
    {
        $card = $this->mf('h-card', ['name' => 'Me', 'url' => 'http://waterpigs.co.uk']);
        $entry = $this->mf('h-entry', ['name' => 'The Entry']);
        $mfs = ['items' => [$entry, $card]];
        $result = getAuthor($entry, $mfs, 'http://waterpigs.co.uk/notes/1234');
        $this->assertEquals('Me', getPlaintext($result, 'name'));
    }
    public function testGetAuthorDerivesMissingUrlFromMf()
    {
        $card = $this->mf('h-card', ['name' => 'Me', 'url' => 'https://waterpigs.co.uk']);
        $entry = $this->mf('h-entry', ['name' => 'The Entry', 'url' => 'https://waterpigs.co.uk/posts/1']);
        $mfs = ['items' => [$entry, $card]];
        $this->assertEquals('Me', getPlaintext(getAuthor($entry, $mfs), 'name'));
    }
    public function testGetAuthorDoesntFallBackToFirstHCard()
    {
        $cards = [$this->mf('h-card', ['name' => 'Bill']), $this->mf('h-card', ['name' => 'James'])];
        $entry = $this->mf('h-entry', ['name' => 'Entry']);
        $mfs = ['items' => $cards];
        $result = getAuthor($entry, $mfs);
        $this->assertEquals(null, $result);
    }
    public function testGetAuthorFindsAuthorWithUrlOfPageRelAuthor()
    {
        $cards = [$this->mf('h-card', ['name' => 'N. T. Author']), $this->mf('h-card', ['name' => 'The Author', 'url' => 'http://example.com'])];
        $entry = $this->mf('h-entry', ['name' => 'Entry']);
        $mfs = ['items' => $cards, 'rels' => ['author' => ['http://example.com']]];
        $result = getAuthor($entry, $mfs);
        $this->assertEquals($cards[1], $result);
    }
    public function testFindMicroformatsByTypeFindsRootMicroformats()
    {
        $mfs = ['items' => [['type' => ['h-card'], 'properties' => ['name' => ['me']]]]];
        $result = findMicroformatsByType($mfs, 'h-card');
        $this->assertEquals('me', getPlaintext($result[0], 'name'));
    }
    public function testFlattenMicroformatsReturnsFlatArrayOfMicroformats()
    {
        $org = $this->mf('h-card', ['name' => 'organisation']);
        $card = $this->mf('h-card', ['name' => 'me', 'org' => [$org]]);
        $entry = $this->mf('h-entry', ['name' => 'blog posting']);
        $card['children'] = [$entry];
        $mfs = ['items' => [$card]];
        $result = flattenMicroformats($mfs);
        $this->assertTrue(\in_array($org, $result));
        $this->assertTrue(\in_array($card, $result));
        $this->assertTrue(\in_array($entry, $result));
    }
    public function testFindMicroformatsByProperty()
    {
        $mfs = ['items' => [$this->mf('h-card', ['name' => 'Me'])]];
        $results = findMicroformatsByProperty($mfs, 'name', 'Me');
        $this->assertEquals(1, \count($results));
    }
    public function testFindMicroformatsByCallable()
    {
        $mfs = ['items' => [$this->mf('h-card', ['url' => 'http://waterpigs.co.uk/'])]];
        $results = findMicroformatsByCallable($mfs, function ($mf) {
            if (!hasProp($mf, 'url')) {
                return \false;
            }
            $urls = $mf['properties']['url'];
            foreach ($urls as $url) {
                if (\parse_url($url, \PHP_URL_HOST) === \parse_url('http://waterpigs.co.uk', \PHP_URL_HOST)) {
                    return \true;
                }
            }
            return \false;
        });
        $this->assertEquals(1, \count($results));
        try {
            findMicroformatsByCallable($mfs, 'not a callable :P');
            $this->fail('No InvalidArgumentException thrown when a non-callable was passed to findMicroformatsByCallable');
        } catch (InvalidArgumentException $e) {
            // Pass!
        }
    }
    public function testFindMicroformatsSearchesSingleMicroformatStructure()
    {
        $card = $this->mf('h-card', ['name' => 'Me']);
        $entry = $this->mf('h-entry', ['author' => [$card], 'name' => 'entry']);
        $results = findMicroformatsByType($entry, 'h-card');
        $this->assertEquals(1, \count($results));
    }
    public function testIsEmbeddedHtml()
    {
        $e = array('value' => '', 'html' => '');
        $this->assertTrue(isEmbeddedHtml($e));
        $this->assertFalse(isEmbeddedHtml(array()));
    }
    public function testIsImgAlt()
    {
        $this->assertFalse(isImgAlt(\false));
        $this->assertFalse(isImgAlt('string'));
        $this->assertFalse(isImgAlt(['value' => 'no alt key tho']));
        $this->assertFalse(isImgAlt(['alt' => 'no value key tho']));
        $this->assertFalse(isImgAlt(['value' => 'yup', 'alt' => 'yup', 0 => 'got numeric keys tho']));
        $this->assertTrue(isImgAlt(['value' => 'yup', 'alt' => 'yup']));
    }
    public function testGetPlaintextProperty()
    {
        $e = $this->mf('h-entry', ['name' => 'text', 'content' => ['text' => 'content', 'html' => '<b>content</b>'], 'author' => [$this->mf('h-card', [], 'name')], 'photo' => [['value' => 'value', 'alt' => 'alt']]]);
        $this->assertEquals('text', getPlaintext($e, 'name'));
        $this->assertEquals('content', getPlaintext($e, 'content'));
        $this->assertEquals('name', getPlaintext($e, 'author'));
        $this->assertNull(getPlaintext($e, 'badprop'));
        $this->assertEquals('fallback', getPlaintext($e, 'badprop', 'fallback'));
        $this->assertEquals('value', getPlaintext($e, 'photo'));
        // Deprecated, tested here to prevent regression and for coverage
        $this->assertEquals('text', getProp($e, 'name'));
    }
    public function testGetPlaintextArray()
    {
        $e = $this->mf('h-entry', ['category' => ['text', 'more'], 'photo' => ['value1', ['value' => 'value2', 'alt' => 'alt']]]);
        $this->assertEquals(['text', 'more'], getPlaintextArray($e, 'category'));
        $this->assertNull(getPlaintextArray($e, 'badprop'));
        $this->assertEquals('fallback', getPlaintextArray($e, 'badprop', 'fallback'));
    }
    public function testGetHtmlProperty()
    {
        $e = $this->mf('h-entry', ['name' => ['"text"<>'], 'content' => ['value' => 'content', 'html' => '<b>content</b>'], 'author' => [$this->mf('h-card', [], '"name"<>')], 'photo' => [['value' => 'value', 'alt' => 'alt']]]);
        $this->assertEquals('&quot;text&quot;&lt;&gt;', getHtml($e, 'name'));
        $this->assertEquals('<b>content</b>', getHtml($e, 'content'));
        $this->assertEquals('&quot;name&quot;&lt;&gt;', getHtml($e, 'author'));
        $this->assertNull(getHtml($e, 'badprop'));
        $this->assertEquals('fallback', getHtml($e, 'badprop', 'fallback'));
    }
    public function testGetImgAlt()
    {
        $e = $this->mf('h-entry', ['photo' => ['pval'], 'featured' => [['value' => 'fval', 'alt' => 'falt']], 'html' => [['value' => 'plain', 'html' => 'html']], 'embedded' => [$this->mf('h-card', [], 'epval')]]);
        $this->assertEquals(['value' => 'pval', 'alt' => ''], getImgAlt($e, 'photo'));
        $this->assertEquals(['value' => 'fval', 'alt' => 'falt'], getImgAlt($e, 'featured'));
        $this->assertEquals(['value' => 'plain', 'alt' => ''], getImgAlt($e, 'html'));
        $this->assertEquals(['value' => 'epval', 'alt' => ''], getImgAlt($e, 'embedded'));
    }
    public function testExpandAuthorExpandsFromLargerHCardsInContext()
    {
        $this->markTestSkipped();
    }
    public function testMergeMicroformatsRecursivelyMerges()
    {
        $this->markTestSkipped();
    }
    public function testGetAuthorDoesntReturnNonHCards()
    {
        $mf = ['items' => [['type' => ['h-entry'], 'properties' => ['url' => ['http://example.com/post/100'], 'name' => ['Some Entry']]], ['type' => ['h-card'], 'properties' => ['url' => ['http://example.com/'], 'name' => ['Mrs. Example']]]]];
        $author = getAuthor($mf['items'][0], $mf, 'http://example.com/post/100');
        $this->assertContains('h-card', $author['type']);
    }
    /**
     * Test that URL path / and empty path match
     */
    public function testUrlsMatchEmptyPath()
    {
        $url1 = 'https://example.com';
        $url2 = 'https://example.com/';
        $this->assertTrue(urlsMatch($url1, $url2));
        $this->assertTrue(urlsMatch($url2, $url1));
    }
    /**
     * Test that URL paths with different trailing slash don't match
     */
    public function testUrlsTrailingSlashDontMatch()
    {
        $url1 = 'https://example.com/path';
        $url2 = 'https://example.com/path/';
        $this->assertFalse(urlsMatch($url1, $url2));
        $this->assertFalse(urlsMatch($url2, $url1));
    }
    /**
     * Test that URLs with different schemes don't match
     */
    public function testUrlsDifferentSchemeDontMatch()
    {
        $url1 = 'http://example.com/path/post/';
        $url2 = 'https://example.com/path/post/';
        $this->assertFalse(urlsMatch($url1, $url2));
        $this->assertFalse(urlsMatch($url2, $url1));
    }
    /**
     * Test anyUrlsMatch() method comparing arrays of URLs
     */
    public function testAnyUrlsMatchParameter1()
    {
        $this->expectException('InvalidArgumentException');
        $array = ['https://example.com/'];
        anyUrlsMatch('string', $array);
    }
    public function testAnyUrlsMatchParameter2()
    {
        $this->expectException('InvalidArgumentException');
        $array = ['https://example.com/'];
        anyUrlsMatch($array, 'string');
    }
    public function testAnyUrlsMatchNoMatch()
    {
        $array1 = ['https://example.com/'];
        $array2 = ['https://example.com/profile'];
        $this->assertFalse(anyUrlsMatch($array1, $array2));
        $this->assertFalse(anyUrlsMatch($array2, $array1));
    }
    public function testAnyUrlsMatch1()
    {
        $array1 = ['https://example.com/'];
        $array2 = ['https://example.com/'];
        $this->assertTrue(anyUrlsMatch($array1, $array2));
        $this->assertTrue(anyUrlsMatch($array2, $array1));
    }
    public function testAnyUrlsMatch2()
    {
        $array1 = ['https://example.com/profile1', 'https://example.com/profile2', 'https://example.com/profile3'];
        $array2 = ['https://example.com/profile3', 'https://example.com/profile2', 'https://example.com/profile5'];
        $this->assertTrue(anyUrlsMatch($array1, $array2));
        $this->assertTrue(anyUrlsMatch($array2, $array1));
    }
    /**
     * Test the h-card `url` == `uid` == page URL method
     * Use the first h-card that meets the criteria
     */
    public function testGetRepresentativeHCardUrlUidSourceMethod()
    {
        $url = 'https://example.com';
        $mfs = ['items' => [['type' => ['h-card'], 'properties' => ['url' => ['https://example.com'], 'uid' => ['https://example.com'], 'name' => ['Correct h-card']]], ['type' => ['h-card'], 'properties' => ['url' => ['https://example.com'], 'uid' => ['https://example.com'], 'name' => ['Second h-card']]]]];
        $repHCard = getRepresentativeHCard($mfs, $url);
        $this->assertNotNull($repHCard);
        $this->assertEquals('Correct h-card', getPlaintext($repHCard, 'name'));
    }
    /**
     * Test the h-card `url` == `rel-me` method
     * Use the first h-card that meets the criteria
     */
    public function testGetRepresentativeHCardUrlRelMeMethod()
    {
        $url = 'https://example.com';
        $mfs = ['items' => [['type' => ['h-card'], 'properties' => ['url' => ['https://example.org'], 'name' => ['Correct h-card']]], ['type' => ['h-card'], 'properties' => ['url' => ['https://example.org'], 'name' => ['Second h-card']]]], 'rels' => ['me' => ['https://example.org']]];
        $repHCard = getRepresentativeHCard($mfs, $url);
        $this->assertNotNull($repHCard);
        $this->assertEquals('Correct h-card', getPlaintext($repHCard, 'name'));
    }
    /**
     * Test the *single* h-card with `url` == page URL method
     */
    public function testGetRepresentativeHCardSingleHCardUrlSourceMethod()
    {
        $url = 'https://example.com';
        $mfs = ['items' => [['type' => ['h-card'], 'properties' => ['url' => ['https://example.com'], 'name' => ['Correct h-card']]]]];
        $repHCard = getRepresentativeHCard($mfs, $url);
        $this->assertNotNull($repHCard);
        $this->assertEquals('Correct h-card', getPlaintext($repHCard, 'name'));
    }
    /**
     * Test no representative h-card when *multiple* h-card with `url` == page URL method
     */
    public function testGetRepresentativeHCardMultipleHCardUrlSourceMethod()
    {
        $url = 'https://example.com';
        $mfs = ['items' => [['type' => ['h-card'], 'properties' => ['url' => ['https://example.com'], 'name' => ['First h-card']]], ['type' => ['h-card'], 'properties' => ['url' => ['https://example.com/user'], 'name' => ['Second h-card']]]]];
        $repHCard = getRepresentativeHCard($mfs, $url);
        $this->assertNull($repHCard);
    }
    /**
     * The getRepresentativeHCard() method used to return other h-* roots.
     * Modified this previous test to ensure the h-entry is not returned
     * even when its `url` == `uid` == page URL
     */
    public function testGetRepresentativeHCardOnlyFindsHCard1()
    {
        $url = 'https://example.com';
        $mf = ['items' => [['type' => ['h-entry'], 'properties' => ['url' => ['https://example.com'], 'uid' => ['https://example.com'], 'name' => ['Not an h-card']]]]];
        $repHCard = getRepresentativeHCard($mf, $url);
        $this->assertNull($repHCard);
    }
    /**
     * The getRepresentativeHCard() method used to return other h-* roots.
     * Modified this previous test to ensure the h-entry is not returned
     * even when `url` == `rel-me`
     */
    public function testGetRepresentativeHCardOnlyFindsHCard2()
    {
        $url = 'https://example.com';
        $mfs = ['items' => [['type' => ['h-entry'], 'properties' => ['url' => ['https://example.org'], 'name' => ['Not an h-card']]]], 'rels' => ['me' => ['https://example.org']]];
        $repHCard = getRepresentativeHCard($mfs, $url);
        $this->assertNull($repHCard);
    }
    /**
     * The getRepresentativeHCard() method used to return other h-* roots.
     * Modified this previous test to ensure the h-entry is not returned
     * even when *single* h-* with `url` == page URL
     */
    public function testGetRepresentativeHCardOnlyFindsHCard3()
    {
        $url = 'https://example.com';
        $mfs = ['items' => [['type' => ['h-entry'], 'properties' => ['url' => ['https://example.com'], 'name' => ['Not an h-card']]]]];
        $repHCard = getRepresentativeHCard($mfs, $url);
        $this->assertNull($repHCard);
    }
    public function testGetRepresentativeHCardIgnoresMultipleUrlPageUrlMatching()
    {
        $url = 'https://example.com';
        $mfs = ['items' => [['type' => ['h-entry'], 'properties' => ['url' => ['https://example.com'], 'name' => ['Not an h-card']]], ['type' => ['h-entry'], 'properties' => ['url' => ['https://example.com'], 'name' => ['Also not an h-card']]]]];
        $repHCard = getRepresentativeHCard($mfs, $url);
        $this->assertNull($repHCard);
    }
    public function testRemoveFalsePositiveRootMicroformats()
    {
        // Based on https://www.lifelog.be/ninety-days-in-a-new-country as of 2022-11-15
        $test = ['items' => [['type' => ['h-full'], 'properties' => [], 'children' => [['type' => ['h-auto'], 'properties' => ['name' => ['']]], ['type' => ['h-entry'], 'properties' => ['name' => ['Ninety days in a new country"']]]]]]];
        $expected = ['items' => [['type' => ['h-entry'], 'properties' => ['name' => ['Ninety days in a new country"']]]]];
        $this->assertEquals($expected, removeFalsePositiveRootMicroformats($test));
    }
}
