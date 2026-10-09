"""Smoke / behaviour tests for jsrecon. Run: python -m unittest -v (from repo root)."""

import json
import os
import sys
import unittest
import xml.dom.minidom

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import beautifier, discovery, reporter
from core.extractor import Extractor, aggregate

JS = r"""
var apiBase="https://api.target.com/v1/users?token=abc";
var AWS="AKIAIOSFODNN7EXAMPLE";
var pw="SuperSecret123!";
var u=location.hash;document.getElementById("o").innerHTML=u;   // source -> sink
eval(location.search);
fetch("http://target.com/legacy");          // in-scope cleartext
fetch("http://cdn.thirdparty.com/x");       // out of scope
var safe=document.getElementById("o").innerHTML;  // lone sink, no... (has source above)
// TODO: remove hardcoded admin password
"""


class ExtractionTests(unittest.TestCase):
    def setUp(self):
        self.ex = Extractor(target_domains={"target.com"})
        self.f = self.ex.extract(beautifier.beautify(JS))
        self.kinds = {(x.category, x.value) for x in self.f}

    def test_secret_detected(self):
        self.assertTrue(any(c == "secrets" and "AKIA" in v for c, v in self.kinds))

    def test_dom_xss_reported_with_source(self):
        dom = [x for x in self.f if x.category == "dom"]
        self.assertTrue(dom, "expected DOM-XSS findings when source+sink co-exist")
        # never rated critical (co-occurrence, not confirmed)
        self.assertTrue(all(x.severity != "critical" for x in dom))

    def test_insecure_http_scoped(self):
        http = [x for x in self.f if x.kind.startswith("Insecure HTTP")]
        vals = " ".join(x.value for x in http)
        self.assertIn("target.com", vals)
        self.assertNotIn("thirdparty.com", vals)  # out-of-scope must be excluded

    def test_entropy_off_by_default(self):
        self.assertFalse(any(x.kind == "High-entropy string" for x in self.f))

    def test_comments_are_info(self):
        for x in self.f:
            if x.category == "comments":
                self.assertEqual(x.severity, "info")

    def test_no_lone_sink_without_source(self):
        ex = Extractor()
        f = ex.extract("document.getElementById('x').innerHTML = y;")  # no source
        self.assertEqual([x for x in f if x.category == "dom"], [])


class RulesTests(unittest.TestCase):
    def test_custom_secret_pattern_and_severity(self):
        import re
        ex = Extractor(extra_secrets=[("Acme", re.compile("acme_[0-9a-f]{6}"),
                                       "critical", 0)])
        f = ex.extract('var t="acme_abcdef";')
        acme = [x for x in f if x.kind == "Acme"]
        self.assertEqual(len(acme), 1)
        self.assertEqual(acme[0].severity, "critical")  # not demoted by placeholder

    def test_exclude_drops_findings(self):
        import re
        ex = Extractor(exclude=[re.compile("cdn\\.example\\.com")])
        f = ex.extract('var a="https://cdn.example.com/x.js";var b="/api/keep";')
        self.assertFalse(any("cdn.example.com" in x.value for x in f))
        self.assertTrue(any("/api/keep" in x.value for x in f))


class AggregateTests(unittest.TestCase):
    def test_dedup_and_count(self):
        ex = Extractor()
        a = ex.extract('fetch("https://api.example.com/orders");')
        b = ex.extract('fetch("https://api.example.com/orders");')
        merged = aggregate([("a.js", a), ("b.js", b)])
        api = [m for m in merged
               if m.category == "links" and m.value == "https://api.example.com/orders"]
        self.assertEqual(len(api), 1)
        self.assertEqual(api[0].count, 2)
        self.assertEqual(sorted(api[0].sources), ["a.js", "b.js"])


class DiscoveryTests(unittest.TestCase):
    def test_find_js_links(self):
        html = '<script src="/a.js"></script><script src="https://x/b.js"></script>'
        links = discovery.find_js_links(html, "https://site/")
        self.assertIn("https://site/a.js", links)
        self.assertIn("https://x/b.js", links)

    def test_webpack_chunk_reconstruction(self):
        js = ('r.u=function(e){return"static/js/"+({1:"feature"}[e]||e)+"."+'
              '{1:"abc123"}[e]+".chunk.js"};')
        self.assertIn("https://s/static/js/feature.abc123.chunk.js",
                      discovery.webpack_chunks(js, "https://s/main.js"))

    def test_sourcemap_detection(self):
        self.assertEqual(
            discovery.find_sourcemap_url("x=1;\n//# sourceMappingURL=app.js.map"),
            "app.js.map")


class ReporterTests(unittest.TestCase):
    def setUp(self):
        ex = Extractor(target_domains={"target.com"})
        res = [("app.js", ex.extract(beautifier.beautify(JS)))]
        self.meta = {"version": "test", "generated": "now",
                     "source_count": 1, "summary": reporter.summarise(res)}
        self.res = res

    def test_json_valid(self):
        json.loads(reporter.render_json(self.res, self.meta))

    def test_xml_wellformed(self):
        xml.dom.minidom.parseString(reporter.render_xml(self.res, self.meta))

    def test_all_formats_nonempty(self):
        for fmt, fn in reporter.RENDERERS.items():
            out = fn(self.res, self.meta)
            self.assertTrue(out and out.strip(), f"{fmt} produced empty output")


if __name__ == "__main__":
    unittest.main(verbosity=2)
