import pytest

import gixy
from gixy.parser.nginx_parser import NginxParser
from gixy.plugins.ssl_ecdh_curve import ssl_ecdh_curve


def _issues(curve_list):
    root = NginxParser(cwd="", allow_includes=False).parse_string(
        "ssl_ecdh_curve {curve_list};".format(curve_list=curve_list)
    )
    plugin = ssl_ecdh_curve({})
    for directive in root.find_recursive("ssl_ecdh_curve"):
        plugin.audit(directive)
    return plugin, plugin.issues


@pytest.mark.parametrize("curve_list,severity,summary", [
    ("X25519MLKEM768:X25519:prime256v1", gixy.severity.MEDIUM, ssl_ecdh_curve.summary),
    ("X25519Kyber768Draft00:X25519", gixy.severity.MEDIUM, ssl_ecdh_curve.summary),
    ("X25519/X25519MLKEM768", gixy.severity.MEDIUM, ssl_ecdh_curve.summary),
    # `?` belongs to one group, not to the rest of its `/` tier
    ("?X25519/X25519MLKEM768", gixy.severity.MEDIUM, ssl_ecdh_curve.summary),
    # OpenSSL 3.3/3.4 only honour `?` as the first character
    ("*X25519MLKEM768:X25519", gixy.severity.MEDIUM, ssl_ecdh_curve.summary),
    ("*?X25519MLKEM768:X25519", gixy.severity.MEDIUM, ssl_ecdh_curve.summary),
    ("X25519:prime256v1:secp384r1", gixy.severity.LOW, ssl_ecdh_curve.classical_summary),
    ("secp384r1", gixy.severity.LOW, ssl_ecdh_curve.classical_summary),
    ("X25519/prime256v1", gixy.severity.LOW, ssl_ecdh_curve.classical_summary),
    ("X25519:prime256v1:?-X25519MLKEM768", gixy.severity.LOW, ssl_ecdh_curve.classical_summary),
    ("X25519/?X25519MLKEM768", gixy.severity.LOW, ssl_ecdh_curve.classical_summary),
    # no OpenSSL release knows the Kyber drafts, so `?` leaves a classical list
    ("?X25519Kyber768Draft00:X25519:prime256v1", gixy.severity.LOW, ssl_ecdh_curve.classical_summary),
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
    "?X25519MLKEM768",
    "?X25519MLKEM768/X25519:prime256v1",
    "?X25519MLKEM768:?SecP256r1MLKEM768/X25519:prime256v1",
    "?*X25519MLKEM768/*X25519:prime256v1",
    "?X25519MLKEM768:?X25519Kyber768Draft00/X25519:prime256v1",
])
def test_not_flagged(curve_list):
    _, issues = _issues(curve_list)
    assert issues == []


@pytest.mark.parametrize("curve_list,expected,unexpected", [
    ("X25519MLKEM768:X25519", ["only exist in OpenSSL 3.5+", "prefix `X25519MLKEM768` with `?`"], ["Kyber"]),
    ("X25519Kyber768Draft00:X25519", ["no OpenSSL release accepts"], ["only exist in OpenSSL 3.5+", "with `?`"]),
    (
        "X25519MLKEM768:X25519Kyber768Draft00",
        ["`X25519MLKEM768` only exist", "`X25519Kyber768Draft00` are pre-standard", "prefix `X25519MLKEM768` with"],
        ["prefix `X25519MLKEM768`, `X25519Kyber768Draft00`"],
    ),
])
def test_startup_failure_reason(curve_list, expected, unexpected):
    _, issues = _issues(curve_list)
    assert len(issues) == 1
    for text in expected:
        assert text in issues[0].reason
    for text in unexpected:
        assert text not in issues[0].reason
