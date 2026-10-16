"""Exercise entry-point dispatch without starting wx or a diagnostic connection."""
import ast
from pathlib import Path
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]


def assigns_flash_utils(node):
    return any(
        isinstance(child, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "flash_utils" for t in child.targets)
        for child in ast.walk(node)
    )


def execute(nodes, namespace):
    tree = ast.Module(body=nodes, type_ignores=[])
    exec(compile(ast.fix_missing_locations(tree), "dispatch", "exec"), namespace)
    return namespace["flash_utils"]


def utilities():
    return {name: object() for name in (
        "simos_flash_utils", "dsg_flash_utils", "dq381_flash_utils",
        "eps_flash_utils", "haldex_flash_utils", "al551_flash_utils",
    )}


class DQ500RoutingTest(unittest.TestCase):
    def test_cli_bosch_and_legacy_profiles(self):
        tree = ast.parse((ROOT / "VW_Flash.py").read_text())
        # Limit execution to the two DSG dispatch statements. Importing the
        # CLI would parse unittest's arguments and load transport libraries.
        nodes = [n for n in tree.body if isinstance(n, ast.If)
                 and assigns_flash_utils(n)
                 and any(isinstance(x, ast.Attribute) and x.attr in ("dq381", "dsg")
                         for x in ast.walk(n.test))]
        self.assertEqual(len(nodes), 2)
        for flag, expected in [("dq500_0dl", "dq381_flash_utils"),
                               ("dq381", "dq381_flash_utils"),
                               ("dl382", "dq381_flash_utils"),
                               ("dq500", "dsg_flash_utils"),
                               ("dsg", "dsg_flash_utils"),
                               ("dq400", "dsg_flash_utils"),
                               ("dq200", "dsg_flash_utils")]:
            with self.subTest(flag=flag):
                ns = utilities()
                flags = dict.fromkeys(("dsg", "dq200", "dq400", "dq500",
                                       "dq500_0dl", "dq381", "dl382"), False)
                flags[flag] = True
                ns["args"] = SimpleNamespace(**flags)
                self.assertIs(execute(nodes, ns), ns[expected])

    def test_both_gui_dispatch_sites(self):
        tree = ast.parse((ROOT / "VW_Flash_GUI.py").read_text())
        helpers = [n for n in tree.body if isinstance(n, ast.FunctionDef)
                   and n.name.startswith("module_selection_is_")]
        panel = next(n for n in tree.body if isinstance(n, ast.ClassDef)
                     and n.name == "FlashPanel")
        for method in ("prepare_file", "flash_bin"):
            fn = next(n for n in panel.body if isinstance(n, ast.FunctionDef)
                      and n.name == method)
            dispatch = next(n for n in fn.body if isinstance(n, ast.If)
                            and assigns_flash_utils(n))
            for index, expected in [(2, "dsg_flash_utils"), (3, "dq381_flash_utils"),
                                    (4, "dsg_flash_utils"), (5, "dsg_flash_utils"),
                                    (6, "dq381_flash_utils")]:
                with self.subTest(method=method, index=index):
                    ns = utilities()
                    ns["self"] = SimpleNamespace(module_choice=SimpleNamespace(
                        GetSelection=lambda: index))
                    self.assertIs(execute(helpers + [dispatch], ns), ns[expected])


if __name__ == "__main__":
    unittest.main()
