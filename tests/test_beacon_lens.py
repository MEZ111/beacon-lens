import unittest

from beacon_lens import analyze, beacon_signals, dns_signals, entropy


class BeaconLensTests(unittest.TestCase):
    def test_detects_periodic_low_variance_flow(self):
        records = [{"ts": 1000 + i * 60, "id.orig_h": "10.0.0.8", "id.resp_h": "203.0.113.9",
                    "id.resp_p": 443, "proto": "tcp", "orig_bytes": 128} for i in range(10)]
        signals = beacon_signals(records)
        self.assertEqual(signals[0].kind, "periodic-connection")
        self.assertGreaterEqual(signals[0].score, 80)

    def test_ignores_jittered_flow(self):
        times = [0, 1, 70, 74, 200, 202, 490]
        records = [{"ts": ts, "id.orig_h": "a", "id.resp_h": "b", "orig_bytes": ts + 1} for ts in times]
        self.assertEqual(beacon_signals(records), [])

    def test_detects_high_entropy_dns_prefixes(self):
        labels = ["a8f3d9c2e7b4", "b7e2a9f4d8c1", "c9a4f7e2b6d8", "d8b3e6f1a9c7", "e7c2a8d4f9b6"]
        records = [{"id.orig_h": "10.0.0.9", "query": f"{label}.example.test"} for label in labels]
        self.assertEqual(dns_signals(records)[0].kind, "dns-encoding-candidate")

    def test_entropy_is_zero_for_repetition(self):
        self.assertEqual(entropy("aaaaaaaa"), 0.0)


if __name__ == "__main__":
    unittest.main()
