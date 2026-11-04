"""Phase 10 test: evaluation harness runs and reports sane measured numbers."""
from __future__ import annotations


def test_evaluation_produces_results_file():
    from pathlib import Path
    from tools.evaluate import main

    text = main()
    out = Path("docs/evaluation_results.md")
    assert out.exists()
    for section in ["Detection", "Reconstruction", "Correlation",
                    "Chain-label", "Performance"]:
        assert section in text
    # measured sanity (not pre-written): B/C detect well, recon perfect, chains 6/6
    assert "| B (timeline+AF) | 0.857 | 1.0 | 0.923 |" in text
    assert "Event-ordering accuracy after store round-trip: **1.0**" in text
    assert "**6/6** scenarios matched" in text
