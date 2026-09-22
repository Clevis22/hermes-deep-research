import importlib.util
import json
import pathlib
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


class ParserTests(unittest.TestCase):
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
    def test_registry_has_91_configured_sources(self):
        self.assertEqual(len(deep_research.S), 91)
        self.assertEqual(set(source["lane"] for source in deep_research.S),
                         set(deep_research.LANES))
        self.assertEqual(
            {source["name"] for source in deep_research.S if source["credential"]},
            {"GitHub code", "Bluesky"},
        )


if __name__ == "__main__":
    unittest.main()
