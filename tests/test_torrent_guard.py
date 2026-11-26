"""Unit tests for files/torrent-guard.py (stdlib only): python3 -m unittest discover tests"""
import importlib.util
import pathlib
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parent.parent / "files" / "torrent-guard.py"
spec = importlib.util.spec_from_file_location("torrent_guard", SCRIPT)
tg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tg)


class RulePlanTest(unittest.TestCase):
    def signature_rules(self, mode):
        _, chains = tg.rule_plan(mode)
        subs = {tg.sub_chain(kind) for kind in tg.KINDS}
        return [r for r in chains[tg.CHAIN] if r[-1] in subs]

    def test_one_rule_per_signature(self):
        for mode in ("monitor", "block"):
            self.assertEqual(len(self.signature_rules(mode)), len(tg.SIGNATURES))

    def test_signatures_goto_sub_chain(self):
        # -j would come back to TORRENT_GUARD after RETURN and let the next signature
        # count the same packet again (a DHT get_peers query matches two rules)
        for mode in ("monitor", "block"):
            for rule in self.signature_rules(mode):
                self.assertEqual(rule[-2], "-g", rule)

    def test_sub_chain_counts_then_returns_in_monitor(self):
        _, chains = tg.rule_plan("monitor")
        for kind in tg.KINDS:
            rules = chains[tg.sub_chain(kind)]
            self.assertEqual(rules[-1][-2:], ["-j", "RETURN"])
            self.assertNotIn("DROP", sum(rules, []))

    def test_version_tag_changes_with_rules(self):
        self.assertNotEqual(tg.rule_plan("monitor")[0], tg.rule_plan("block")[0])


class ConntrackTest(unittest.TestCase):
    def test_fanout_skips_common_ports(self):
        lines = "\n".join([
            "tcp 6 300 ESTABLISHED src=10.8.0.2 dst=1.1.1.1 sport=5000 dport=443 src=1.1.1.1 dst=9.9.9.9 sport=443 dport=5000",
            "udp 17 30 src=10.8.0.2 dst=2.2.2.2 sport=6881 dport=51413 src=2.2.2.2 dst=9.9.9.9 sport=51413 dport=6881",
            "udp 17 30 src=10.8.0.2 dst=3.3.3.3 sport=6881 dport=6881 src=3.3.3.3 dst=9.9.9.9 sport=6881 dport=6881",
            "udp 17 30 src=10.8.0.9 dst=4.4.4.4 sport=1 dport=2 src=4.4.4.4 dst=9.9.9.9 sport=2 dport=1",
        ])
        stats = tg.parse_conntrack(lines, {"10.8.0.2": "key"})
        self.assertEqual(stats, {"10.8.0.2": {"flows": 3, "dsts": 3, "udp_hi": 2,
                                              "fan_hosts": 2, "fan_ports": 2}})


if __name__ == "__main__":
    unittest.main()
