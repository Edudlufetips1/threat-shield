#!/usr/bin/env python3
"""
calibrate_threat_index.py

DISCLAIMER: This is a dev/calibration utility, not part of the core
application. It was generated with AI assistance (Claude) to help derive
starting BaseIndex/ScalingScalar values for the ThreatScorer sigmoid from
real rawScore data, since deriving them by hand analytically isn't
straightforward. Values it recommends were reviewed and verified against
the actual pipeline output before being adopted, not used blindly.

Parses debug log output from EvaluateVulnerability() and computes the
BaseIndex / ScalingScalar values that will center your threatIndex output
around a target mean/std (default: mean=62.5, std=12.5, matching a
16% / 68% / 13.5% bell-curve split on the 0-100 scale).

Usage:
    1. In scoring.go, right before `return threatIndex`, add:

        fmt.Printf("DEBUG rawScore=%.2f threatIndex=%.2f\n", rawScore, threatIndex)

    2. Run your pipeline against real KEV data and redirect stdout to a file:

        go run . > run_log.txt 2>&1
        # (in another terminal) python collector.py

    3. Run this script against that log:

        python calibrate_threat_index.py run_log.txt

    4. Drop the printed BaseIndex/ScalingScalar into your ThreatScorer struct.
"""

import argparse
import re
import statistics
import sys

LINE_PATTERN = re.compile(r"rawScore=([-\d.]+)")


def extract_raw_scores(path: str) -> list[float]:
    scores = []
    with open(path, "r") as f:
        for line in f:
            match = LINE_PATTERN.search(line)
            if match:
                scores.append(float(match.group(1)))
    return scores


def recommend_parameters(scores: list[float], target_mean: float, target_std: float):
    mean_r = statistics.mean(scores)
    std_r = statistics.pstdev(scores)  # population std; use stdev() if you prefer sample std

    # Derived from the local-linear approximation of the sigmoid:
    #   threatIndex ≈ 50 + 25 * (rawScore - BaseIndex) / ScalingScalar
    # Solving for BaseIndex/ScalingScalar so the OUTPUT hits target_mean/target_std:
    base_index = mean_r - std_r
    scaling_scalar = 2 * std_r

    return mean_r, std_r, base_index, scaling_scalar


def main():
    parser = argparse.ArgumentParser(description="Calibrate ThreatScorer sigmoid parameters from real rawScore data.")
    parser.add_argument("logfile", help="Path to a log file containing 'rawScore=X.XX' lines")
    parser.add_argument("--target-mean", type=float, default=62.5, help="Desired mean threatIndex (default 62.5)")
    parser.add_argument("--target-std", type=float, default=12.5, help="Desired std dev of threatIndex (default 12.5)")
    args = parser.parse_args()

    scores = extract_raw_scores(args.logfile)
    if not scores:
        print(f"No 'rawScore=' lines found in {args.logfile}. Did you add the debug print statement?", file=sys.stderr)
        sys.exit(1)

    mean_r, std_r, base_index, scaling_scalar = recommend_parameters(scores, args.target_mean, args.target_std)

    print(f"Parsed {len(scores)} rawScore samples from {args.logfile}")
    print(f"  rawScore mean:   {mean_r:.2f}")
    print(f"  rawScore std:    {std_r:.2f}")
    print(f"  rawScore min:    {min(scores):.2f}")
    print(f"  rawScore max:    {max(scores):.2f}")
    print()
    print(f"Recommended calibration for target mean={args.target_mean}, std={args.target_std}:")
    print(f"  BaseIndex     = {base_index:.2f}")
    print(f"  ScalingScalar = {scaling_scalar:.2f}")
    print()
    print("Sanity check — sample threatIndex values with these parameters:")
    import math
    for pct in [10, 25, 50, 75, 90]:
        idx = int(len(scores) * pct / 100)
        sample = sorted(scores)[min(idx, len(scores) - 1)]
        z = (sample - base_index) / scaling_scalar
        threat_index = 100.0 / (1 + math.exp(-z))
        print(f"  rawScore={sample:.2f} (p{pct}) -> threatIndex={threat_index:.2f}")


if __name__ == "__main__":
    main()
