'use strict'

const test = require('tape')
const fastURI = require('..')

test('parse marks malformed authority and port inputs as errors', (t) => {
  const malformedCases = [
    {
      input: 'http://[::1]foo',
      expectedError: 'URI path must start with "/" when authority is present.'
    },
    {
      input: 'http://[::1]:80abc/path',
      expectedError: 'URI path must start with "/" when authority is present.'
    },
    {
      input: 'http://example.com:80abc/path',
      expectedError: 'URI path must start with "/" when authority is present.'
    },
    {
      input: 'http://[::1]:65536',
      expectedError: 'URI port is malformed.'
    }
  ]

  t.plan(malformedCases.length)

  malformedCases.forEach(({ input, expectedError }) => {
    t.equal(fastURI.parse(input).error, expectedError, input)
  })
})

test('normalize does not canonicalize malformed URLs into different valid URLs', (t) => {
  const malformedCases = [
    'http://[::1]foo',
    'http://[::1]:80abc/path',
    'http://example.com:80abc/path',
    'http://[::1]:65536'
  ]

  t.plan(malformedCases.length)

  malformedCases.forEach((input) => {
    t.equal(fastURI.normalize(input), input, input)
  })
})

test('equal returns false when either side is malformed', (t) => {
  const malformedPairs = [
    ['http://[::1]foo', 'http://[::1]/foo'],
    ['http://[::1]:80abc/path', 'http://[::1]/abc/path'],
    ['http://example.com:80abc/path', 'http://example.com/abc/path'],
    ['http://[::1]:65536', 'http://[::1]:65536/']
  ]

  t.plan(malformedPairs.length)

  malformedPairs.forEach(([left, right]) => {
    t.equal(fastURI.equal(left, right), false, `${left} != ${right}`)
  })
})

test('normalize preserves encoded authority delimiters in host', (t) => {
  const cases = [
    ['http://trusted.com%40evil.com/', 'http://trusted.com%40evil.com/'],
    ['http://example.com%3A8080/', 'http://example.com%3A8080/'],
    ['http://example.com%2Fevil.com/path', 'http://example.com%2Fevil.com/path'],
    ['http://example.com%23fragment/path', 'http://example.com%23fragment/path'],
    ['http://example.com%3Fq=evil/path', 'http://example.com%3Fq=evil/path'],
    ['http://user%3Apass%40evil.com/', 'http://user%3Apass%40evil.com/'],
    ['http://user@trusted.com%40evil.com/', 'http://user@trusted.com%40evil.com/'],
    ['https://trusted.com%40evil.com/', 'https://trusted.com%40evil.com/'],
    ['ws://trusted.com%40evil.com/chat', 'ws://trusted.com%40evil.com/chat'],
    ['wss://trusted.com%40evil.com/chat', 'wss://trusted.com%40evil.com/chat']
  ]

  t.plan(cases.length)

  cases.forEach(([input, expected]) => {
    t.equal(fastURI.normalize(input), expected, input)
  })
})

test('parse preserves encoded authority delimiters in host', (t) => {
  const cases = [
    ['http://trusted.com%40evil.com/', 'trusted.com%40evil.com'],
    ['http://example.com%3A8080/', 'example.com%3A8080'],
    ['http://user%3Apass%40evil.com/', 'user%3Apass%40evil.com']
  ]

  t.plan(cases.length)

  cases.forEach(([input, expectedHost]) => {
    t.equal(fastURI.parse(input).host, expectedHost, input)
  })
})

test('equal returns false when encoded delimiters differ from live delimiters', (t) => {
  const pairs = [
    ['http://trusted.com%40evil.com/', 'http://trusted.com@evil.com/'],
    ['http://example.com%3A8080/', 'http://example.com:8080/']
  ]

  t.plan(pairs.length)

  pairs.forEach(([left, right]) => {
    t.equal(fastURI.equal(left, right, {}), false, `${left} != ${right}`)
  })
})

test('resolve preserves encoded authority delimiters', (t) => {
  const result = fastURI.resolve('http://base.com/', '//trusted.com%40evil.com/path')
  const parsed = fastURI.parse(result)

  t.plan(1)
  t.notEqual(parsed.host, 'evil.com', '//trusted.com%40evil.com/path')
})

test('serialize escapes authority delimiters in host field', (t) => {
  const result = fastURI.serialize({ scheme: 'http', host: 'trusted.com@evil.com', path: '/' })
  const parsed = fastURI.parse(result)

  t.plan(1)
  t.notEqual(parsed.host, 'evil.com', 'host: trusted.com@evil.com')
})

test('normalize does not double-decode %2540 into a live @', (t) => {
  const result = fastURI.normalize('http://trusted.com%2540evil.com/')
  const parsed = fastURI.parse(result)

  t.plan(1)
  t.notEqual(parsed.host, 'trusted.com@evil.com', 'http://trusted.com%2540evil.com/')
})

test('parse canonicalises IDN / Unicode hosts to their ASCII form', (t) => {
  const cases = [
    {
      input: 'http://127。0。0。1/',
      expectedHost: '127.0.0.1',
      description: 'full-width ideographic stops as octet separators'
    },
    {
      input: 'http://ｅxample.com/',
      expectedHost: 'example.com',
      description: 'fullwidth e as first letter'
    },
    {
      input: 'http://納豆.example.org/',
      expectedHost: 'xn--99zt52a.example.org',
      description: 'CJK label requiring punycode'
    }
  ]

  t.plan(cases.length * 2)

  cases.forEach(({ input, expectedHost, description }) => {
    const parsed = fastURI.parse(input)
    t.notOk(parsed.error, `parse should not set error: ${description}`)
    t.equal(parsed.host, expectedHost, `host canonicalised to ASCII: ${description}`)
  })
})

test('parse rejects a literal backslash in the authority as malformed (RFC 3986)', (t) => {
  // Regression for the host-confusion bypass: a literal "\" is invalid RFC 3986
  // syntax and must be flagged malformed, not silently rewritten. Otherwise "\"
  // acts as a host delimiter here while Node's native URL parses a different
  // host, defeating a host-based SSRF/redirect/origin allowlist.
  const cases = [
    'http://evil.com\\@allowed.com',
    'https://169.254.169.254\\@trusted.example.com',
    'http://127.0.0.1\\@public.example.com',
    'https://attacker.com\\@api.internal',
    'http://a\\@b',
    'ws://evil.com\\@allowed.com/chat',
    'wss://evil.com\\@allowed.com/chat',
    'http://evil.com\\%40allowed.com',
    '//evil.com\\@allowed.com'
  ]

  t.plan(cases.length)

  cases.forEach((input) => {
    t.equal(
      fastURI.parse(input).error,
      'URI authority must not contain a literal backslash.',
      input
    )
  })
})

test('normalize does not canonicalize a literal-backslash URI into a different valid URL', (t) => {
  const cases = [
    'http://evil.com\\@allowed.com',
    'https://attacker.com\\@api.internal'
  ]

  t.plan(cases.length)

  cases.forEach((input) => {
    t.equal(fastURI.normalize(input), input, input)
  })
})

test('parse leaves percent-encoded %5C untouched as encoded data (not rejected)', (t) => {
  // Only the literal "\" byte is rejected; %5C stays valid encoded data and
  // does not diverge from the native URL parser, so it must not be flagged.
  const input = 'http://evil.com%5C@allowed.com'
  const parsed = fastURI.parse(input)

  t.plan(2)
  t.notOk(parsed.error, '%5C is valid encoded data, not malformed')
  t.equal(parsed.host, new URL(input).hostname, '%5C host matches native URL (no divergence)')
})

test('parse does not reject a literal backslash in the query or fragment', (t) => {
  // The rejection is scoped to the authority/path (the host-confusion surface);
  // a backslash after "?"/"#" is normalized as encoded data as before.
  const parsed = fastURI.parse('http://host.example.com/?x=\\y#z\\w')

  t.plan(2)
  t.notOk(parsed.error, 'backslash in query/fragment does not mark the URI malformed')
  t.equal(parsed.host, 'host.example.com', 'host parsed normally')
})

test('parse rejects a malformed authority introducer (\\\\, /\\, \\/) in place of //', (t) => {
  // Regression: "\\", "/\\", "\\/" after the scheme colon are not valid authority
  // introducers. Node's URL treats "\\" as interchangeable with "/" on special
  // schemes, so "http:\\\\evil.com/path" would be parsed as host "evil.com" by
  // Node, but fast-uri must reject it as malformed to prevent SSRF/redirect bypass.
  const cases = [
    'http:\\\\evil.com/path',
    'http:/\\evil.com/path',
    'http:\\/evil.com/path',
    'ws:\\\\evil.com/chat',
    'wss:\\\\evil.com/chat',
    'ftp:\\\\evil.com/',
    '\\\\evil.com/path'
  ]

  t.plan(cases.length)

  cases.forEach((input) => {
    t.equal(
      fastURI.parse(input).error,
      'URI authority must not contain a literal backslash.',
      input
    )
  })
})

test('normalize does not canonicalize a malformed-authority-introducer URI', (t) => {
  const cases = [
    'http:\\\\evil.com/path',
    'http:/\\evil.com/path'
  ]

  t.plan(cases.length)

  cases.forEach((input) => {
    t.equal(fastURI.normalize(input), input, input)
  })
})

test('equal returns false for malformed-authority-introducer URIs', (t) => {
  const pairs = [
    ['http:\\\\evil.com/path', 'http://evil.com/path'],
    ['http:/\\evil.com/path', 'http://evil.com/path']
  ]

  t.plan(pairs.length)

  pairs.forEach(([left, right]) => {
    t.equal(fastURI.equal(left, right), false, `${left} != ${right}`)
  })
})

test('resolve throws on malformed authority introducer', (t) => {
  // resolve() returns a plain string with no error field, so the only safe
  // behavior is to throw when either component has a malformed authority.
  const pairs = [
    ['https://allowed.com/', '\\\\evil.com/path'],
    ['\\\\evil.com/path', 'https://allowed.com/'],
    ['https://allowed.com/', 'http:/\\evil.com/path'],
    ['https://allowed.com/', 'http:\\/evil.com/path']
  ]

  t.plan(pairs.length)

  pairs.forEach(([base, rel]) => {
    t.throws(
      () => fastURI.resolve(base, rel),
      /URI authority must not contain a literal backslash/,
      `${base} + ${rel}`
    )
  })
})

test('parse rejects a whitespace-split authority introducer (TAB, LF, CR)', (t) => {
  // The WHATWG URL parser removes TAB (U+0009), LF (U+000A) and CR (U+000D) from
  // the input before parsing, so a stripped character wedged into the introducer
  // ("/<TAB>\\", "/<TAB>/", or a leading "<TAB>//") reaches an authority in Node
  // while fast-uri would otherwise fold it into the path. These must be rejected
  // like the adjacent "\\", "/\\", "\\/" forms.
  const cases = [
    { input: '/\t\\evil.com/path', expectedError: 'URI authority must not contain a literal backslash.' },
    { input: '/\t/evil.com/path', expectedError: 'URI authority introducer must not contain whitespace.' },
    { input: '/\n\\evil.com/path', expectedError: 'URI authority must not contain a literal backslash.' },
    { input: '/\r\\evil.com/path', expectedError: 'URI authority must not contain a literal backslash.' },
    { input: '\t//evil.com/path', expectedError: 'URI authority introducer must not contain whitespace.' },
    { input: '\t/\\evil.com/path', expectedError: 'URI authority must not contain a literal backslash.' },
    { input: 'https:/\t/evil.com/path', expectedError: 'URI authority introducer must not contain whitespace.' }
  ]

  t.plan(cases.length)

  cases.forEach(({ input, expectedError }) => {
    t.equal(fastURI.parse(input).error, expectedError, JSON.stringify(input))
  })
})

test('resolve throws on a whitespace-split authority introducer', (t) => {
  const pairs = [
    ['https://allowed.com/', '/\t\\evil.com/path'],
    ['https://allowed.com/', '/\t/evil.com/path'],
    ['https://allowed.com/', '/\n\\evil.com/path'],
    ['/\t/evil.com/path', 'https://allowed.com/']
  ]

  t.plan(pairs.length)

  pairs.forEach(([base, rel]) => {
    t.throws(
      () => fastURI.resolve(base, rel),
      /URI authority (must not contain a literal backslash|introducer must not contain whitespace)/,
      `${JSON.stringify(base)} + ${JSON.stringify(rel)}`
    )
  })
})

test('parse does not reject valid authority introducer patterns', (t) => {
  // No false positives: "//" introducer and scheme-less "//" must be valid.
  const cases = [
    'http://good.com/',
    'https://good.com/',
    'ws://good.com/chat',
    'wss://good.com/chat',
    'ftp://good.com/',
    '//good.com/path',
    '/absolute/path',
    'relative/path'
  ]

  t.plan(cases.length)

  cases.forEach((input) => {
    const parsed = fastURI.parse(input)
    t.notOk(parsed.error, input)
  })
})

test('CVE-2026-75931: resolve canonicalises the host using the final resolved scheme', (t) => {
  const cases = [
    {
      base: 'http://trusted.example/base',
      relative: '//127。0。0。1/private',
      expected: 'http://127.0.0.1/private',
      expectedHost: '127.0.0.1',
      description: 'scheme-relative loopback host'
    },
    {
      base: 'https://ex­ample.com/base',
      relative: 'child',
      expected: 'https://example.com/child',
      expectedHost: 'example.com',
      description: 'host inherited from the base'
    },
    {
      base: 'http://trusted.example/base',
      relative: 'http://ex​ample.com/',
      expected: 'http://example.com/',
      expectedHost: 'example.com',
      description: 'absolute relative reference'
    }
  ]

  t.plan(cases.length * 2)

  cases.forEach(({ base, relative, expected, expectedHost, description }) => {
    const resolved = fastURI.resolve(base, relative)
    t.equal(resolved, expected, description)
    t.equal(fastURI.parse(resolved).host, expectedHost, `${description} reparses consistently`)
  })
})

test('CVE-2026-75931: resolve applies domain canonicalisation only when the effective scheme opts in', (t) => {
  const host = 'ex­ample.com'

  t.plan(2)
  t.equal(
    fastURI.resolve('uri://trusted.example/', `//${host}/`),
    `uri://${host}/`,
    'an unsupported scheme preserves the host'
  )
  t.equal(
    fastURI.resolve('http://trusted.example/', `//${host}/`, { unicodeSupport: true }),
    `http://${host}/`,
    'unicodeSupport preserves the Unicode host'
  )
})

test('CVE-2026-75931: resolve throws when the final scheme cannot canonicalise the host', (t) => {
  const invalidHost = '‍.example'
  const cases = [
    ['http://trusted.example/', `//${invalidHost}/`],
    [`https://${invalidHost}/base`, 'child'],
    ['http://trusted.example/', `http://${invalidHost}/`]
  ]

  t.plan(cases.length)

  cases.forEach(([base, relative]) => {
    t.throws(
      () => fastURI.resolve(base, relative),
      /Host's domain name can not be converted to ASCII/,
      `${base} + ${relative}`
    )
  })
})

test('CVE-2026-75899: hostname normalization never decodes an escape more than once', (t) => {
  const encodedLocalhost = 'http://%256c%256f%2563%2561%256c%2568%256f%2573%2574/'
  const encodedLoopback = '//127%252e0%252e0%252e1/private'
  const encodedMetadataAddress = '//169%252E254%252E169%252E254/latest/meta-data/'

  t.plan(7)
  t.equal(fastURI.normalize(encodedLocalhost), encodedLocalhost, 'nested hostname letters remain encoded')
  t.equal(fastURI.normalize(encodedLoopback), encodedLoopback, 'nested IPv4 dots remain encoded')
  t.equal(
    fastURI.resolve('https://safe.example/', encodedLoopback),
    'https://127%252e0%252e0%252e1/private',
    'resolve does not turn nested dots into a loopback address'
  )
  t.equal(
    fastURI.resolve('https://allowed.com/api/v1/', encodedMetadataAddress),
    'https://169%252e254%252e169%252e254/latest/meta-data/',
    'resolve does not turn nested dots into a metadata address'
  )
  t.equal(
    fastURI.normalize('http://allowed.com%255Cevil.com/'),
    'http://allowed.com%255Cevil.com/',
    'normalize does not activate a nested backslash'
  )
  t.equal(
    fastURI.serialize({ scheme: 'http', host: '%256cocalhost', path: '/' }),
    'http://%256cocalhost/',
    'component serialization preserves an encoded percent sign'
  )
  t.equal(
    fastURI.equal(encodedLocalhost, 'http://localhost/', {}),
    false,
    'nested escapes do not compare equal to their twice-decoded target'
  )
})

test('CVE-2026-75899: hostname normalization decodes only current unreserved escapes', (t) => {
  t.plan(4)
  t.equal(fastURI.normalize('x://%6cocalhost/'), 'x://localhost/', 'a current unreserved escape is decoded')
  t.equal(fastURI.normalize('x://%256cocalhost/'), 'x://%256cocalhost/', 'an encoded percent is preserved')
  t.equal(fastURI.normalize('x://host%2540evil/'), 'x://host%2540evil/', 'a nested authority delimiter stays inert')
  t.equal(fastURI.normalize('x://%2525/'), 'x://%2525/', 'nested encoded percent signs stay encoded')
})

test('CVE-2026-75899: host conversion failures are not treated as comparable URLs', (t) => {
  const malformedHost = 'http://trusted.test%2540evil.test/'

  t.plan(3)
  t.equal(fastURI.normalize(malformedHost), malformedHost, 'normalization preserves the failing input')
  t.equal(fastURI.equal(malformedHost, malformedHost, {}), false, 'equal rejects a failed host conversion')
  t.throws(
    () => fastURI.resolve(malformedHost, 'child', { domainHost: true }),
    /Host's domain name can not be converted to ASCII/,
    'resolve propagates a host conversion failure'
  )
})

test('CVE-2026-75975: unterminated bracket hosts are rejected in resolve', (t) => {
  t.plan(2)
  t.throws(
    () => fastURI.resolve('http://[fe80/', 'child'),
    /URI host is malformed\./,
    'an unterminated base host is not waved through as an IP literal'
  )
  t.throws(
    () => fastURI.resolve('http://example.com/', '//[fe80/private'),
    /URI host is malformed\./,
    'an unterminated reference host is not waved through as an IP literal'
  )
})

test('CVE-2026-84292: a misplaced IP-literal bracket can not move the authority to another host', (t) => {
  const uri = 'http://user@[@127.0.0.1:8123/admin'
  const modes = [
    ['default', undefined],
    ['Unicode', { unicodeSupport: true }]
  ]

  t.plan(modes.length * 4)

  modes.forEach(([mode, options]) => {
    const parsed = fastURI.parse(uri, options)
    t.notEqual(parsed.host, '127.0.0.1', `${mode} mode parse does not yield host 127.0.0.1`)
    t.equal(parsed.error, 'URI host is malformed.', `${mode} mode parse rejects the host`)
    t.notEqual(
      fastURI.parse(fastURI.normalize(uri, options), options).host,
      '127.0.0.1',
      `${mode} mode normalize does not reparse to host 127.0.0.1`
    )
    t.throws(
      () => fastURI.resolve('http://trusted.example/', uri, options),
      /URI host is malformed\./,
      `${mode} mode resolve rejects the reference`
    )
  })
})

test('CVE-2026-84292: a component port can not inject a new authority', (t) => {
  t.plan(3)
  t.throws(
    () => fastURI.serialize({ scheme: 'http', host: 'trusted.example', port: '@127.0.0.1:8124', path: '/app' }),
    /URI port is malformed\./,
    'serialize rejects a port carrying authority delimiters'
  )
  t.throws(
    () => fastURI.resolveComponent({ scheme: 'http', host: 'trusted.example', port: '@127.0.0.1:8124' }, { path: 'app' }),
    /URI port is malformed\./,
    'resolveComponent rejects a base port carrying authority delimiters'
  )
  t.equal(
    fastURI.equal({ scheme: 'http', host: 'trusted.example', port: '@127.0.0.1:8124' }, 'http://trusted.example:@127.0.0.1:8124/'),
    false,
    'equal does not match a URI whose authority host is 127.0.0.1'
  )
})

const DANGEROUS_SCHEME = /^(?:javascript|data|vbscript)$/i
const DANGEROUS_SCHEME_PREFIX = /^(?:javascript|data|vbscript):/i
const ENCODED_SCHEME_INPUTS = [
  '%6Aavascript:alert(1)',
  '%4A%41%56%41%53%43%52%49%50%54:alert(1)',
  '%u006Aavascript:alert(1)',
  'j%61vascript:alert(1)',
  '%64ata:text/html,<script>alert(1)</script>',
  'vb%73cript:msgbox(1)'
]

test('CVE-2026-110306: parse never decodes a percent-encoded scheme', (t) => {
  t.plan(ENCODED_SCHEME_INPUTS.length * 2)

  ENCODED_SCHEME_INPUTS.forEach((uri) => {
    const encodedScheme = uri.slice(0, uri.indexOf(':'))
    const parsed = fastURI.parse(uri)
    t.equal(parsed.scheme, encodedScheme, `${uri} keeps its scheme encoded`)
    t.notOk(DANGEROUS_SCHEME.test(parsed.scheme), `${uri} does not parse as a javascript/data/vbscript scheme`)
  })
})

test('CVE-2026-110306: normalization cannot synthesize a scheme from encoded input', (t) => {
  t.plan(ENCODED_SCHEME_INPUTS.length * 2)

  ENCODED_SCHEME_INPUTS.forEach((uri) => {
    const encodedScheme = uri.slice(0, uri.indexOf(':'))
    const normalized = fastURI.normalize(uri)
    t.notOk(DANGEROUS_SCHEME_PREFIX.test(normalized), `${uri} does not normalize to a javascript/data/vbscript URI`)
    t.equal(normalized.indexOf(encodedScheme + ':'), 0, `${uri} normalizes with its scheme still encoded`)
  })
})

test('CVE-2026-110306: resolve cannot synthesize a scheme from encoded input', (t) => {
  t.plan(ENCODED_SCHEME_INPUTS.length)

  // A percent-encoded scheme is not a valid RFC 3986 scheme, so resolve()
  // rejects it rather than emitting it (CVE-2026-76172) or decoding it.
  ENCODED_SCHEME_INPUTS.forEach((uri) => {
    t.throws(
      () => fastURI.resolve('https://example.com/app/', uri),
      /URI scheme is malformed\./,
      `${uri} is rejected by resolve instead of resolving to a javascript/data/vbscript URI`
    )
  })
})

test('CVE-2026-110306: an encoded scheme does not alias or select a plain scheme', (t) => {
  t.plan(5)
  t.equal(fastURI.equal('%68ttp://a/', 'http://a/'), false, 'encoded scheme does not alias a plain scheme')
  t.equal(
    fastURI.normalize('ht%74ps://example.com:443'),
    'ht%74ps://example.com:443',
    'HTTPS normalization does not run for an encoded scheme'
  )

  const ws = fastURI.parse('w%73://example.com/a?b')
  t.equal(ws.scheme, 'w%73', 'the ws scheme stays encoded')
  t.equal(ws.resourceName, undefined, 'ws parsing does not run for an encoded scheme')

  t.throws(
    () => fastURI.serialize({ scheme: '%6Aavascript', path: 'alert(1)' }),
    /URI scheme is malformed\./,
    'an encoded component scheme can not serialize as javascript:'
  )
})

const MALFORMED_SCHEME_ERROR = 'URI scheme is malformed.'

test('CVE-2026-76172: a scheme that would decode into reserved delimiters is rejected', (t) => {
  const malformed = [
    '%2f%2fevil.example:/pwn',
    '%2F%2Fevil.example:/pwn',
    'ht%74p%2f%2fevil.example:/x',
    '%u002f%u002fevil.example:/pwn'
  ]

  t.plan(malformed.length * 2)

  malformed.forEach((uri) => {
    t.equal(fastURI.parse(uri).error, MALFORMED_SCHEME_ERROR, `parse rejects ${uri}`)
    t.equal(fastURI.normalize(uri), uri, `normalize preserves the failing input ${uri}`)
  })
})

test('CVE-2026-76172: resolve throws when a component scheme carries delimiters', (t) => {
  t.plan(2)
  t.throws(
    () => fastURI.resolve('%2f%2fevil.example:/pwn', 'child'),
    /URI scheme is malformed/,
    'resolve rejects a malformed base scheme'
  )
  t.throws(
    () => fastURI.serialize({ scheme: '%2f%2fevil.example', path: '/pwn' }),
    /URI scheme is malformed/,
    'serialize rejects a component scheme that would decode to delimiters'
  )
})

test('CVE-2026-76172: valid schemes are still accepted and an encoded scheme is never decoded', (t) => {
  t.plan(8)
  // RFC 3986 section 3.1 does not allow percent-encoding in a scheme
  // (CVE-2026-110306), so an encoded scheme is rejected rather than decoded.
  const encoded = fastURI.parse('htt%70://example.com/')
  t.equal(encoded.error, MALFORMED_SCHEME_ERROR, 'an encoded scheme is malformed')
  t.equal(encoded.scheme, 'htt%70', 'an encoded scheme is not decoded to http')
  t.equal(fastURI.normalize('HTTP://example.com/'), 'http://example.com/', 'scheme is lowercased')
  t.equal(fastURI.parse('HTTP://example.com/').scheme, 'http', 'parse lowercases a valid scheme')
  t.equal(fastURI.parse('a1+.-:value').scheme, 'a1+.-', 'every RFC 3986 scheme character is accepted')
  t.equal(fastURI.parse('a1+.-:value').error, undefined, 'a valid scheme is not an error')
  t.equal(fastURI.serialize({ scheme: 'foo+bar', path: 'value' }), 'foo+bar:value', 'a valid component scheme is serialized')
  t.equal(fastURI.resolve('HTTP://example.com/a/b', 'c'), 'http://example.com/a/c', 'resolve accepts a valid scheme')
})

test('CVE-2026-76172: no API emits a delimiter-bearing scheme that reparses as an authority', (t) => {
  t.plan(11)
  t.throws(
    () => fastURI.resolve('http://example.com/', '%2f%2fevil.example:/pwn'),
    /URI scheme is malformed/,
    'resolve rejects a malformed reference scheme'
  )
  t.throws(
    () => fastURI.serialize({ scheme: '//evil.example', path: '/pwn' }),
    /URI scheme is malformed/,
    'serialize rejects a raw component scheme containing delimiters'
  )
  t.throws(
    () => fastURI.normalize({ scheme: '%2f%2fevil.example', path: '/pwn' }),
    /URI scheme is malformed/,
    'normalize rejects a component scheme that would decode to delimiters'
  )
  t.throws(
    () => fastURI.normalize({ scheme: '//evil.example', path: '/pwn' }),
    /URI scheme is malformed/,
    'normalize rejects a raw component scheme containing delimiters'
  )
  t.throws(
    () => fastURI.resolveComponent(
      { scheme: 'http', host: 'example.com', path: '/' },
      { scheme: '%2f%2fevil.example', path: '/pwn' }
    ),
    /URI scheme is malformed/,
    'resolveComponent rejects a relative component scheme that would decode to delimiters'
  )
  t.throws(
    () => fastURI.resolveComponent(
      { scheme: 'http', host: 'example.com', path: '/' },
      { scheme: '//evil.example', path: '/pwn' }
    ),
    /URI scheme is malformed/,
    'resolveComponent rejects a relative component scheme containing delimiters'
  )
  t.notEqual(fastURI.parse('%2f%2fevil.example:/pwn').scheme, '//evil.example', 'parse does not decode the scheme into delimiters')
  t.equal(fastURI.equal('%2f%2fevil.example:/pwn', '%2f%2fevil.example:/pwn'), false, 'equal fails closed on malformed string schemes')
  t.equal(fastURI.equal('%2f%2fevil.example:/pwn', '//evil.example:/pwn'), false, 'equal does not match the reparsed authority')
  const component = { scheme: '//evil.example', path: '/pwn' }
  t.equal(fastURI.equal(component, component), false, 'equal fails closed on malformed component schemes')
  t.equal(fastURI.equal(component, '//evil.example:/pwn'), false, 'equal does not throw on, or match, a malformed component scheme')
})

test('CVE-2026-76172: schemes outside the RFC 3986 grammar are rejected', (t) => {
  const malformed = [
    '%0d%0aSet-Cookie:%20sid=attacker:/p',
    'foo%3Abar:value',
    'foo%2Fbar:value',
    '1http://example.com/',
    'foo_bar:value',
    'éxample:value',
    // U+212A KELVIN SIGN lowercases to an ASCII "k"
    'Kttp://example.com/',
    // U+017F LATIN SMALL LETTER LONG S uppercases to an ASCII "S"
    'ſcheme:value'
  ]

  t.plan(malformed.length * 3 + 2)

  malformed.forEach((uri) => {
    t.equal(fastURI.parse(uri).error, MALFORMED_SCHEME_ERROR, `parse rejects ${JSON.stringify(uri)}`)
    t.equal(fastURI.normalize(uri), uri, `normalize preserves the failing input ${JSON.stringify(uri)}`)
    t.equal(fastURI.equal(uri, uri, {}), false, `equal fails closed on ${JSON.stringify(uri)}`)
  })

  t.notOk(fastURI.normalize('%0d%0aSet-Cookie:%20sid=attacker:/p').includes('\r\n'), 'normalized output contains no raw CRLF')
  t.throws(
    () => fastURI.serialize({ scheme: 'x\r\nSet-Cookie', path: ' sid=attacker' }),
    /URI scheme is malformed/,
    'serialize rejects a component scheme carrying a raw CRLF'
  )
})

test('CVE-2026-76172: a scheme handler can not install a malformed scheme while serializing', (t) => {
  t.plan(1)

  fastURI.SCHEMES['x-cve-2026-76172'] = {
    scheme: 'x-cve-2026-76172',
    parse: (component) => component,
    serialize: (component) => {
      component.scheme = '//evil.example'
      return component
    }
  }

  try {
    t.throws(
      () => fastURI.serialize({ scheme: 'x-cve-2026-76172', path: '/pwn' }),
      /URI scheme is malformed/,
      'the scheme is revalidated after scheme specific serialization'
    )
  } finally {
    delete fastURI.SCHEMES['x-cve-2026-76172']
  }
})
