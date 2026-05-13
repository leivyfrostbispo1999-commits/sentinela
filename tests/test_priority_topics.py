import pytest
from services.common.pipeline_resilience import get_priority_topic, get_all_priority_topics, normalize_priority

def test_normalize_priority():
    assert normalize_priority("high") == "high"
    assert normalize_priority("HIGH") == "high"
    assert normalize_priority("medium") == "medium"
    assert normalize_priority("low") == "low"
    assert normalize_priority("unknown") == "medium"
    assert normalize_priority(None) == "medium"

def test_get_priority_topic():
    base = "alerts"
    assert get_priority_topic(base, "high") == "alerts_high"
    assert get_priority_topic(base, "medium") == "alerts"
    assert get_priority_topic(base, "low") == "alerts_low"
    assert get_priority_topic(base, "critical") == "alerts"  # default to medium

def test_get_all_priority_topics():
    base = "alerts"
    topics = get_all_priority_topics(base)
    assert len(topics) == 3
    assert "alerts" in topics
    assert "alerts_high" in topics
    assert "alerts_low" in topics
