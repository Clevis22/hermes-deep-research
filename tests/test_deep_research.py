import importlib.util
import json
import pathlib
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "deep_research", ROOT / "scripts" / "deep_research.py"
)
deep_research = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(deep_research)


class QueryShapeTests(unittest.TestCase):
    def test_cve_suffix_is_not_treated_as_a_cwe(self):
        query = deep_research.Q("CVE-2021-44228")
        self.assertEqual(query.cves, ["CVE-2021-44228"])
        self.assertEqual(query.cwes, [])

    def test_ipv4_is_not_treated_as_a_domain(self):
        query = deep_research.Q("1.1.1.1")
        self.assertEqual(query.ipv4, "1.1.1.1")
        self.assertIsNone(query.domain)

    def test_ipv6_repo_and_package_shapes(self):
        self.assertEqual(deep_research.Q("2001:4860:4860::8888").ip,
                         "2001:4860:4860::8888")
        self.assertEqual(
            deep_research.Q("https://github.com/expressjs/express").repo,
            "github.com/expressjs/express",
        )
        package = deep_research.Q("npm:@colors/colors@1.5.0").package
        self.assertEqual(package, {
            "ecosystem": "npm", "system": "NPM",
            "name": "@colors/colors", "version": "1.5.0",
        })


class TransportTests(unittest.TestCase):
    def test_bulk_feed_cache_avoids_second_network_call(self):
        with tempfile.TemporaryDirectory() as cache_dir, \
                mock.patch.dict("os.environ", {"DEEP_RESEARCH_CACHE": cache_dir}), \
                mock.patch.object(deep_research, "http", return_value=("payload", None)) as fetch:
            first = deep_research.cached_http("https://example.test/feed", max_age=60)
            second = deep_research.cached_http("https://example.test/feed", max_age=60)

        self.assertEqual(first, ("payload", None))
        self.assertEqual(second, ("payload", None))
        fetch.assert_called_once()


class AutoRoutingTests(unittest.TestCase):
    @staticmethod
    def jev_response(**scores):
        answers = {
            f"lane_{lane}": {"type": "noul", "noul": scores.get(lane, 0.05)}
            for lane in deep_research.AUTO_LANE_QUESTIONS
        }
        return json.dumps({
            "model": "typesafe/jev-1.13-test",
            "answers": answers,
            "usage": {"input_tokens": 321, "output_tokens": 18},
        })

    def test_jev_routes_ambiguous_query_to_top_relevant_lanes(self):
        body = self.jev_response(
            academic=0.94, security=0.88, news=0.69, patents=0.68
        )
        with mock.patch.object(deep_research, "http", return_value=(body, None)):
            route = deep_research.auto_route(
                "residential proxy detection research", api_key="test-key"
            )

        self.assertEqual(route["mode"], "auto-jev")
        self.assertEqual(route["selected_lanes"], ["web", "academic", "security"])
        self.assertEqual(route["probabilities"]["academic"], 0.94)
        self.assertFalse(route["fallback"])
        self.assertNotIn("news", route["selected_lanes"])

    def test_exact_cve_forces_security_even_when_jev_says_no(self):
        with mock.patch.object(deep_research, "http") as mocked_http:
            route = deep_research.auto_route("CVE-2021-44228", api_key="test-key")

        mocked_http.assert_not_called()
        self.assertEqual(route["mode"], "auto-rules-exact")
        self.assertIn("security", route["selected_lanes"])
        self.assertIn("security", route["forced_lanes"])
        self.assertEqual(route["reasons"]["security"], "exact security/network identifier")

    def test_exact_doi_forces_academic_without_package_lanes(self):
        route = deep_research.auto_route("10.1234/example", api_key="test-key")

        self.assertEqual(route["selected_lanes"], ["web", "academic"])
        self.assertNotIn("code", route["selected_lanes"])
        self.assertNotIn("security", route["selected_lanes"])

    def test_network_identifiers_force_osint_without_jev(self):
        with mock.patch.object(deep_research, "http") as mocked_http:
            route = deep_research.auto_route("AS15169", api_key="test-key")

        mocked_http.assert_not_called()
        self.assertEqual(route["selected_lanes"], ["web", "security", "osint"])

    def test_repo_forces_code_and_supply_chain_security(self):
        route = deep_research.auto_route(
            "https://github.com/expressjs/express", api_key="test-key"
        )

        self.assertEqual(route["selected_lanes"], ["web", "code", "security"])
        self.assertEqual(route["reasons"]["code"], "repository identifier")

    def test_missing_key_uses_conservative_local_fallback(self):
        route = deep_research.auto_route("latest court ruling", api_key="")

        self.assertEqual(route["mode"], "auto-rules-fallback")
        self.assertTrue(route["fallback"])
        self.assertIn("news", route["selected_lanes"])
        self.assertIn("regulatory", route["selected_lanes"])
        self.assertIn("OPENROUTER_API_KEY", route["note"])

    def test_local_fallback_keeps_security_for_proxy_research(self):
        route = deep_research.auto_route(
            "residential proxy detection research", api_key=""
        )

        self.assertIn("academic", route["selected_lanes"])
        self.assertIn("security", route["selected_lanes"])

    def test_jev_payload_batches_all_lane_questions(self):
        body = self.jev_response(reference=0.9, news=0.8)
        captured = {}

        def fake_http(url, **kwargs):
            captured["url"] = url
            captured["payload"] = json.loads(kwargs["data"])
            return body, None

        with mock.patch.object(deep_research, "http", side_effect=fake_http):
            deep_research.jev_lane_scores(deep_research.Q("OpenAI history"), api_key="secret")

        self.assertEqual(captured["url"], deep_research.OPENROUTER_DECISIONS_URL)
        self.assertEqual(captured["payload"]["model"], deep_research.JEV_MODEL)
        self.assertEqual(
            set(captured["payload"]["questions"]),
            {f"lane_{lane}" for lane in deep_research.AUTO_LANE_QUESTIONS},
        )

    def test_low_probability_runner_up_is_not_forced(self):
        body = self.jev_response(reference=0.94, academic=0.13)
        with mock.patch.object(deep_research, "http", return_value=(body, None)):
            route = deep_research.auto_route(
                "history of the Eiffel Tower", api_key="test-key"
            )

        self.assertEqual(route["selected_lanes"], ["web", "reference"])


class ParserTests(unittest.TestCase):
    def test_github_advisory_and_deps_parsers(self):
        advisory = [{
            "ghsa_id": "GHSA-test-1234-5678",
            "cve_id": "CVE-2024-1234",
            "html_url": "https://github.com/advisories/GHSA-test-1234-5678",
            "summary": "Example vulnerability",
            "severity": "high",
            "identifiers": [{"type": "CVE", "value": "CVE-2024-1234"}],
            "vulnerabilities": [{
                "package": {"ecosystem": "npm", "name": "example"},
                "first_patched_version": {"identifier": "2.0.0"},
            }],
        }]
        rows, _ = deep_research._github_advisory_parse(
            json.dumps(advisory), "https://api.github.test", deep_research.Q("CVE-2024-1234"), 5
        )
        self.assertIn("CVE-2024-1234", rows[0][0])
        self.assertIn("fixed=2.0.0", rows[0][1])

        package = {
            "packageKey": {"system": "NPM", "name": "express"},
            "versions": [
                {"versionKey": {"version": "4.0.0"}, "isDefault": False},
                {"versionKey": {"version": "5.0.0"}, "isDefault": True},
            ],
        }
        rows, _ = deep_research._deps_parse(
            json.dumps(package), "https://deps.test", deep_research.Q("npm:express"), 5
        )
        self.assertIn("2 versions", rows[0][0])
        self.assertIn("default=5.0.0", rows[0][1])

    def test_scorecard_parser_labels_score_as_heuristic(self):
        payload = {
            "date": "2026-09-21T00:00:00Z",
            "repo": {"name": "github.com/acme/widget"},
            "score": 8.1,
            "checks": [{"name": "Pinned-Dependencies", "score": 3,
                        "reason": "dependencies not pinned", "documentation": {}}],
        }
        rows, _ = deep_research._scorecard_parse(
            json.dumps(payload), "https://scorecard.test",
            deep_research.Q("github:acme/widget"), 5,
        )
        self.assertIn("8.1/10", rows[0][0])
        self.assertIn("not a vulnerability verdict", rows[0][1])

    def test_rdap_gleif_and_ofac_parsers(self):
        rdap = {
            "objectClassName": "domain", "ldhName": "EXAMPLE.COM",
            "status": ["active"],
            "events": [{"eventAction": "registration", "eventDate": "1995-08-14T00:00:00Z"}],
            "entities": [], "links": [],
        }
        rows, _ = deep_research._rdap_parse(
            json.dumps(rdap), "https://rdap.test", deep_research.Q("example.com"), 5
        )
        self.assertIn("EXAMPLE.COM", rows[0][0])
        self.assertIn("registered=1995-08-14", rows[0][1])

        gleif = {"meta": {"pagination": {"total": 1}}, "data": [{
            "id": "549300TESTTESTTEST12",
            "attributes": {"lei": "549300TESTTESTTEST12", "entity": {
                "legalName": {"name": "Acme Corp"}, "status": "ACTIVE",
                "headquartersAddress": {"city": "Boston", "country": "US"},
            }, "registration": {"status": "ISSUED"}},
        }]}
        rows, note = deep_research._gleif_parse(
            json.dumps(gleif), "https://gleif.test", deep_research.Q("Acme Corp"), 5
        )
        self.assertIn("Acme Corp", rows[0][0])
        self.assertIn("not proof", note)

        xml = """<sdnList><sdnEntry><uid>1</uid><firstName>Jane</firstName>
        <lastName>Example</lastName><sdnType>Individual</sdnType>
        <programList><program>TEST</program></programList></sdnEntry></sdnList>"""
        rows, note = deep_research._ofac_parse(
            xml, "https://ofac.test", deep_research.Q("is Jane Example sanctioned by OFAC?"), 5
        )
        self.assertIn("Potential OFAC name match", rows[0][0])
        self.assertIn("manual identity verification required", rows[0][1])
        self.assertIn("does not establish", note)

    def test_openphish_only_returns_target_domain_matches(self):
        query = deep_research.Q("example.com")
        feed = "\n".join([
            "https://unrelated.test/login",
            "https://example.com/account",
            "https://secure.example.com/auth",
            "not a URL",
        ])

        rows, note = deep_research._openphish_parse(
            feed, "https://openphish.com/feed.txt", query, 10
        )

        self.assertIsNone(note)
        self.assertEqual(len(rows), 2)
        self.assertTrue(all("example.com" in row[2] for row in rows))
        self.assertIsNone(deep_research._openphish_build(deep_research.Q("CVE-2021-44228")))

    def test_capec_uses_mitre_relationships_not_matching_numeric_ids(self):
        payload = {
            "Weaknesses": [{
                "ID": "89",
                "Name": "Improper Neutralization in an SQL Command",
                "RelatedAttackPatterns": ["108", "66", "7"],
            }]
        }
        rows, note = deep_research._capec_parse(
            json.dumps(payload), "https://cwe.example/89",
            deep_research.Q("CWE-89 SQL injection"), 10,
        )

        self.assertIsNone(note)
        self.assertEqual([row[0].split()[0] for row in rows],
                         ["CAPEC-7", "CAPEC-66", "CAPEC-108"])
        self.assertNotIn("CAPEC-89", {row[0].split()[0] for row in rows})

    def test_openaire_parser_handles_singletons_and_lists(self):
        payload = {
            "response": {"results": {"result": [{
                "metadata": {"oaf:entity": {"oaf:result": {
                    "title": [{"$": "A useful paper"}],
                    "creator": {"$": "Ada Researcher"},
                    "dateofacceptance": {"$": "2024-01-02"},
                    "pid": [
                        {"@classid": "other", "$": "123"},
                        {"@classid": "doi", "$": "10.1234/example"},
                    ],
                }}},
            }]}}
        }
        rows, note = deep_research._openaire_parse(
            json.dumps(payload), "https://openaire.example",
            deep_research.Q("useful paper"), 5,
        )

        self.assertIsNone(note)
        self.assertEqual(rows, [(
            "A useful paper",
            "2024-01-02 Ada Researcher",
            "https://doi.org/10.1234/example",
        )])


class AccountingTests(unittest.TestCase):
    def test_merged_corroborating_sources_all_count_as_hits(self):
        sources = [
            {"name": "First", "lane": "web"},
            {"name": "Second", "lane": "web"},
        ]

        def fake_run_one(source, query, limit):
            title = "unrelated result" if source["name"] == "First" else "alpha beta result"
            return ([deep_research.Result(
                source["name"], "web", title, "", "https://example.test/item"
            )], None, True)

        with mock.patch.object(deep_research, "S", sources), \
                mock.patch.object(deep_research, "run_one", side_effect=fake_run_one):
            result = deep_research.research(
                "alpha beta", lanes=("web",), limit=5, workers=1
            )

        self.assertEqual(result["sources_with_hits"], 2)
        self.assertEqual(result["unrelated_matches"], 0)
        self.assertEqual(set(result["findings"][0].sources), {"First", "Second"})


class ReportingTests(unittest.TestCase):
    @staticmethod
    def result_with_findings(findings):
        return {
            "query": "alpha beta",
            "shape": {"cve": [], "domain": None, "url": False},
            "sources_with_hits": 1,
            "sources_queried": 2,
            "duplicates_collapsed": 0,
            "elapsed_s": 0.1,
            "findings": findings,
            "by_lane": {"web": [row for row in findings if not row.off_topic]},
            "errors": [],
            "unrelated_matches": sum(row.off_topic for row in findings),
            "empty_sources": [],
            "skipped_not_applicable": [],
        }

    def test_markdown_sources_exclude_off_topic_rows_by_default(self):
        useful = deep_research.Result(
            "Useful source", "web", "Useful result", "", "https://example.test/useful"
        )
        unrelated = deep_research.Result(
            "Noisy source", "web", "Unrelated result", "", "https://example.test/noise",
            off_topic=True,
        )
        report = deep_research.markdown_sources_block({"findings": [useful, unrelated]})

        self.assertIn("Useful result", report)
        self.assertNotIn("Unrelated result", report)

    def test_markdown_report_has_one_clean_sources_block(self):
        useful = deep_research.Result(
            "Useful source", "web", "Useful result", "", "https://example.test/useful"
        )
        unrelated = deep_research.Result(
            "Noisy source", "web", "Unrelated result", "", "https://example.test/noise",
            off_topic=True,
        )
        result = self.result_with_findings([useful, unrelated])

        with_sources = deep_research.markdown_report(result)
        without_sources = deep_research.markdown_report(result, include_sources=False)

        self.assertEqual(with_sources.count("\n## Sources\n"), 1)
        self.assertIn("Useful result", with_sources.split("\n## Sources\n", 1)[1])
        self.assertNotIn("Unrelated result", with_sources.split("\n## Sources\n", 1)[1])
        self.assertNotIn("\n## Sources\n", without_sources)

    def test_github_code_search_is_skipped_without_a_token(self):
        with mock.patch.object(deep_research, "_dotenv_value", return_value=None):
            self.assertIsNone(deep_research._github_code_build(deep_research.Q("parser")))


class RegistryTests(unittest.TestCase):
    def test_registry_has_101_configured_sources(self):
        self.assertEqual(len(deep_research.S), 101)
        self.assertEqual(set(source["lane"] for source in deep_research.S),
                         set(deep_research.LANES))
        self.assertEqual(
            {source["name"] for source in deep_research.S if source["credential"]},
            {"GitHub code", "Bluesky"},
        )


if __name__ == "__main__":
    unittest.main()
