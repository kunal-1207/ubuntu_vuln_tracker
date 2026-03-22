import pytest
from scanner.patch_checker import PatchChecker

def test_version_comparison():
    checker = PatchChecker()
    
    # Test basic numeric versions
    assert checker.compare_versions("1.0.0", "1.0.1") is True
    assert checker.compare_versions("1.1.0", "1.0.1") is False
    assert checker.compare_versions("1.0", "1.0") is False
    
    # Test Ubuntu-style versions
    assert checker.compare_versions("1.2.3-0ubuntu1", "1.2.3-0ubuntu2") is True
    assert checker.compare_versions("1.2.3-0ubuntu1", "1.2.4-0ubuntu1") is True
    
    # Test fallback naive compare if packaging is missing or fails
    assert checker._naive_compare("1.10", "1.2") is False # 1.10 > 1.2
    assert checker._naive_compare("2.1-1", "2.1-2") is True

def test_naive_compare_edge_cases():
    checker = PatchChecker()
    assert checker._naive_compare("1.0.0", "1.0.0-1") is True
    assert checker._naive_compare("1.0.1", "1.0.0") is False
