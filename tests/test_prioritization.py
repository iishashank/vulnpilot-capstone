import unittest

from backend.prioritization import classify_priority_band, finding_priority_score


class PrioritizationTests(unittest.TestCase):
    def test_kev_and_epss_raise_priority(self):
        score = finding_priority_score(7.5, kev=True, exploit=False, epss=0.62)
        self.assertGreater(score, 12.0)
        self.assertEqual(
            classify_priority_band(7.5, kev=True, exploit=False, epss=0.62),
            "CRITICAL",
        )

    def test_low_signal_finding_stays_low(self):
        score = finding_priority_score(2.1, kev=False, exploit=False, epss=0.01)
        self.assertLess(score, 4.0)
        self.assertEqual(
            classify_priority_band(2.1, kev=False, exploit=False, epss=0.01, fallback="LOW"),
            "LOW",
        )


if __name__ == "__main__":
    unittest.main()
