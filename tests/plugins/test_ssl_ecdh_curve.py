import pytest

import gixy
from gixy.parser.nginx_parser import NginxParser
from gixy.plugins.ssl_ecdh_curve import ssl_ecdh_curve


def _audit(config):
    root = NginxParser(cwd="", allow_includes=False).parse_string(config)
    plugin = ssl_ecdh_curve({})
    for directive in root.find_recursive("ssl_ecdh_curve"):
        plugin.audit(directive)
    return plugin, plugin.issues


def _issues(curve_list):
    return _audit("ssl_ecdh_curve {curve_list};".format(curve_list=curve_list))


@pytest.mark.parametrize("curve_list,severity,summary", [
    ("X25519MLKEM768:X25519:prime256v1", gixy.severity.MEDIUM, ssl_ecdh_curve.summary),
    ("X25519Kyber768Draft00:X25519", gixy.severity.MEDIUM, ssl_ecdh_curve.summary),
    ("X25519/X25519MLKEM768", gixy.severity.MEDIUM, ssl_ecdh_curve.summary),
    # `?` belongs to one group, not to the rest of its `/` tier
    ("?X25519/X25519MLKEM768", gixy.severity.MEDIUM, ssl_ecdh_curve.summary),
    # OpenSSL 3.3/3.4 only honour `?` as the first character
    ("*X25519MLKEM768:X25519", gixy.severity.MEDIUM, ssl_ecdh_curve.summary),
    ("*?X25519MLKEM768:X25519", gixy.severity.MEDIUM, ssl_ecdh_curve.summary),
    ("?X25519MLKEM768", gixy.severity.MEDIUM, ssl_ecdh_curve.pq_only_summary),
    ("?X25519MLKEM768:?SecP256r1MLKEM768", gixy.severity.MEDIUM, ssl_ecdh_curve.pq_only_summary),
    ("?X25519MLKEM768:X25519:-X25519", gixy.severity.MEDIUM, ssl_ecdh_curve.pq_only_summary),
    ("AUTO", gixy.severity.MEDIUM, ssl_ecdh_curve.rejected_summary),
    ("Auto", gixy.severity.MEDIUM, ssl_ecdh_curve.rejected_summary),
    ("?DEFAULT", gixy.severity.MEDIUM, ssl_ecdh_curve.rejected_summary),
    ("DEFAULT:-DEFAULT", gixy.severity.MEDIUM, ssl_ecdh_curve.rejected_summary),
    ("X25519:prime256v1:secp384r1", gixy.severity.LOW, ssl_ecdh_curve.classical_summary),
    ("secp384r1", gixy.severity.LOW, ssl_ecdh_curve.classical_summary),
    ("X25519/prime256v1", gixy.severity.LOW, ssl_ecdh_curve.classical_summary),
    ("X25519:prime256v1:?-X25519MLKEM768", gixy.severity.LOW, ssl_ecdh_curve.classical_summary),
    ("X25519:prime256v1:-X25519MLKEM768", gixy.severity.LOW, ssl_ecdh_curve.classical_summary),
    # `-` also removes a group listed earlier
    ("?X25519MLKEM768:X25519:-X25519MLKEM768", gixy.severity.LOW, ssl_ecdh_curve.classical_summary),
    ("X25519/?X25519MLKEM768", gixy.severity.LOW, ssl_ecdh_curve.classical_summary),
    # no OpenSSL release knows the Kyber drafts, so `?` leaves a classical list
    ("?X25519Kyber768Draft00:X25519:prime256v1", gixy.severity.LOW, ssl_ecdh_curve.classical_summary),
    ("DEFAULT:-X25519MLKEM768", gixy.severity.LOW, ssl_ecdh_curve.classical_summary),
    ("default:-x25519mlkem768", gixy.severity.LOW, ssl_ecdh_curve.classical_summary),
    # adding the hybrid back after removing it from DEFAULT puts it in the last tier
    ("DEFAULT:-X25519MLKEM768:X25519MLKEM768", gixy.severity.LOW, ssl_ecdh_curve.classical_summary),
    ("?X25519MLKEM768:X25519:prime256v1", gixy.severity.INFORMATION, ssl_ecdh_curve.shared_tier_summary),
    ("X25519:?X25519MLKEM768", gixy.severity.INFORMATION, ssl_ecdh_curve.shared_tier_summary),
    (
        "?X25519MLKEM768:?SecP256r1MLKEM768:X25519/prime256v1",
        gixy.severity.INFORMATION,
        ssl_ecdh_curve.shared_tier_summary,
    ),
])
def test_flagged(curve_list, severity, summary):
    plugin, issues = _issues(curve_list)
    assert len(issues) == 1
    issue = issues[0]
    assert (issue.severity or plugin.severity) == severity
    assert (issue.summary or plugin.summary) == summary
    assert issue.reason


@pytest.mark.parametrize("curve_list", [
    "auto",
    "DEFAULT",
    "default",
    "DEFAULT:-X448",
    "DEFAULT/X25519MLKEM768",
    "?X25519MLKEM768/X25519:prime256v1",
    "?X25519MLKEM768:?SecP256r1MLKEM768/X25519:prime256v1",
    "?*X25519MLKEM768/*X25519:prime256v1",
    "?X25519MLKEM768:?X25519Kyber768Draft00/X25519:prime256v1",
    # OpenSSL trims spaces around group names and separators
    '"?X25519MLKEM768: ?SecP256r1MLKEM768 / X25519"',
    '" ?X25519MLKEM768 / X25519 : prime256v1 "',
])
def test_not_flagged(curve_list):
    _, issues = _issues(curve_list)
    assert issues == []


@pytest.mark.parametrize("curve_list,expected,unexpected", [
    (
        "X25519MLKEM768:X25519",
        ["only exist in OpenSSL 3.5+", "make `?` the first character of `X25519MLKEM768`"],
        ["Kyber", "OpenSSL 3.5 syntax"],
    ),
    ("X25519Kyber768Draft00:X25519", ["no OpenSSL release accepts"], ["only exist in OpenSSL 3.5+", "`?`"]),
    (
        "X25519MLKEM768:X25519Kyber768Draft00",
        ["`X25519MLKEM768` only exist", "`X25519Kyber768Draft00` are pre-standard", "character of `X25519MLKEM768` if"],
        ["`X25519MLKEM768`, `X25519Kyber768Draft00` if"],
    ),
    # adding `?` cannot make a list with OpenSSL 3.5 syntax load on 3.3/3.4
    ("X25519/X25519MLKEM768", ["OpenSSL 3.5 syntax", "no prefix makes it load"], ["first character"]),
    ("X25519MLKEM768:X25519:-X448", ["OpenSSL 3.5 syntax"], ["first character"]),
    ("X25519MLKEM768:*X25519", ["OpenSSL 3.5 syntax"], ["first character"]),
    ("*X25519MLKEM768:X25519", ["make `?` the first character of `*X25519MLKEM768`"], ["OpenSSL 3.5 syntax"]),
])
def test_startup_failure_reason(curve_list, expected, unexpected):
    _, issues = _issues(curve_list)
    assert len(issues) == 1
    for text in expected:
        assert text in issues[0].reason
    for text in unexpected:
        assert text not in issues[0].reason


@pytest.mark.parametrize("config,severities", [
    # `ssl_conf_command Groups` is applied after `ssl_ecdh_curve` and replaces its list
    ("server { ssl_conf_command Groups X25519MLKEM768:X25519; ssl_ecdh_curve X25519:prime256v1; }", []),
    ("server { ssl_conf_command Curves X25519MLKEM768:X25519; ssl_ecdh_curve X25519:prime256v1; }", []),
    ("http { ssl_conf_command Groups X25519MLKEM768:X25519; server { ssl_ecdh_curve X25519; } }", []),
    ("server { ssl_conf_command Groups X25519; ssl_ecdh_curve ?X25519MLKEM768:X25519; }", []),
    # a level that sets its own ssl_conf_command does not inherit the enclosing ones
    (
        "http { ssl_conf_command Groups X25519MLKEM768; server { ssl_conf_command Options -SessionTicket; "
        "ssl_ecdh_curve X25519; } }",
        [gixy.severity.LOW],
    ),
    ("server { ssl_conf_command Options -SessionTicket; ssl_ecdh_curve X25519; }", [gixy.severity.LOW]),
    # an override in one server does not cover an http-level list used by the others
    ("http { ssl_ecdh_curve X25519; server { ssl_conf_command Groups X25519MLKEM768:X25519; } }", [gixy.severity.LOW]),
    # OpenSSL still parses ssl_ecdh_curve first, so startup failures are reported regardless
    ("server { ssl_conf_command Groups X25519; ssl_ecdh_curve X25519MLKEM768:X25519; }", [gixy.severity.MEDIUM]),
    ("server { ssl_conf_command Groups X25519; ssl_ecdh_curve ?X25519MLKEM768; }", [gixy.severity.MEDIUM]),
    ("server { ssl_conf_command Groups X25519; ssl_ecdh_curve AUTO; }", [gixy.severity.MEDIUM]),
])
def test_ssl_conf_command_groups(config, severities):
    plugin, issues = _audit(config)
    assert [issue.severity or plugin.severity for issue in issues] == severities
