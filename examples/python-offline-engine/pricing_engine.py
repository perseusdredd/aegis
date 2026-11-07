# Counter-Showcase #5: Offline Python Pricing & Valuation Engine
#
# Run pre-flight audit:
#   npx bla-shield audit examples/python-offline-engine/pricing_engine.py
# Protect against REA:
#   npx bla-shield protect examples/python-offline-engine/pricing_engine.py

from __future__ import annotations


def calculate_dynamic_quote(base_units: int, volatility_bps: int, tier_multiplier: int) -> int:
    """Computes proprietary offline derivatives pricing quote."""
    spread = (base_units * volatility_bps) // 10_000
    adjusted = (base_units + spread) * max(1, tier_multiplier)
    return adjusted ^ 0x5A3C
