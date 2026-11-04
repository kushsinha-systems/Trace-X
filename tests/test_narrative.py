"""Phase 9 tests: narrative layer is summarisation-only with enforced framing."""
from __future__ import annotations


def _combined_case():
    from tools.synth_generator import generate
    from backend.app.normalize import coerce_event
    from backend.app.antiforensics import detect_all
    from backend.app.chains import attach_rules, detect_chains

    events = [coerce_event(d) for d in generate("combined")[0]]
    findings = detect_all(events)
    chains = attach_rules(detect_chains(events, findings=findings), findings)
    assert chains
    return events, findings, chains


def test_narrative_cites_every_step_and_validates():
    from backend.app.narrative import narrate_chain, validate_narrative

    events, findings, chains = _combined_case()
    n = narrate_chain(chains[0], events, findings, use_llm=False)
    assert "The system identified a sequence consistent with" in n.text
    for eid in chains[0].event_ids:
        assert eid[:8] in n.text  # every factual claim traceable
    assert "Limitation:" in n.text
    validate_narrative(n.text)  # must not raise


def test_forbidden_framing_rejected():
    import pytest

    from backend.app.narrative import validate_narrative

    for bad in ["AI determined the user was malicious",
                "AI determined the attacker deleted the logs",
                "The perpetrator is guilty"]:
        with pytest.raises(ValueError):
            validate_narrative(bad)


def test_llm_offline_falls_back_to_template():
    from backend.app.narrative import narrate_chain, ollama_polish

    events, findings, chains = _combined_case()
    plain = narrate_chain(chains[0], events, findings, use_llm=False).text
    assert ollama_polish(plain, model="no-such-model", timeout_s=2) == plain
    # use_llm=True with no Ollama running must still return the valid template
    n = narrate_chain(chains[0], events, findings, use_llm=True)
    assert plain.splitlines()[0] in n.text or n.text == plain
