"""
Juice Shop Benchmark Runner.
Executes the JuiceShopBenchmarkSuite and outputs the la-v-f metrics.
"""
import argparse
import json
from ersec.benchmarking.juiceshop import JuiceShopBenchmarkSuite

def main():
    parser = argparse.ArgumentParser(description="Run ERSEC Juice Shop Benchmark")
    parser.add_argument("--url", required=True, help="Juice Shop base URL")
    parser.add_argument("--admin-token", required=True, help="Admin session token")
    parser.add_argument("--user-token", required=True, help="Regular user session token")
    parser.add_argument("--output", default="juiceshop_results.json", help="Output report file")

    args = parser.parse_args()

    print(f"[*] Initializing Juice Shop Benchmark Suite...")
    suite = JuiceShopBenchmarkSuite(
        base_url=args.url,
        admin_token=args.admin_token,
        user_token=args.user_token
    )

    print(f"[*] Running {len(suite.get_cases())} cases...")
    results = suite.run_suite()

    print("\n" + "="*40)
    print("ERSEC JUICE SHOP BENCHMARK RESULTS")
    print("="*40)

    quality = results["quality"]
    if "note" in quality:
        print(f"Note: {quality['note']}")
    else:
        print(f"Precision: {quality['precision']}")
        print(f"Recall:    {quality['recall']}")
        print(f"F1 Score:   {quality['f1']}")
        print(f"TP: {quality['true_positives']} | FP: {quality['false_positives']} | FN: {quality['false_negatives']}")
        print(f"Coverage: {quality['scorable_coverage']:.2%}")

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, sort_keys=True)

    print(f"\n[*] Full report written to {args.output}")

if __name__ == "__main__":
    main()
