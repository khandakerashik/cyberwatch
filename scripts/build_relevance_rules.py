#!/usr/bin/env python3
"""Build the browser's deterministic rules from the shared relevance policy."""
import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def render():
    rules = json.loads((ROOT / 'data/news-relevance-rules.json').read_text(encoding='utf-8'))
    return '// Generated from data/news-relevance-rules.json by scripts/build_relevance_rules.py.\nexport default ' + json.dumps(rules, ensure_ascii=False, indent=2) + ';\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    target = ROOT / 'dist/news-relevance-rules.js'
    expected = render()
    if args.check:
        if not target.exists() or target.read_text(encoding='utf-8') != expected:
            raise SystemExit('Browser relevance rules are stale. Run python scripts/build_relevance_rules.py.')
        print('Browser and collector relevance rules match.')
    else:
        target.write_text(expected, encoding='utf-8')


if __name__ == '__main__':
    main()
