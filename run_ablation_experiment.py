
import argparse
import subprocess
import sys
import json
from pathlib import Path
from datetime import datetime
from typing import List


DEFAULT_BINARY_DIR = r"D:\ongoing_project\agent_mcp_sec_projects\work_version\test_12\matched_exe\matched_exe"
DEFAULT_VM_HOSTS = "192.168.52.147,192.168.52.148,192.168.52.144,192.168.52.145"
DEFAULT_MODELS = ["deepseek-r1:7b"]
DEFAULT_LLM_TYPE = "ollama"
DEFAULT_RUNS = ["Iter", "Iter+PE2"]

AVAILABLE_MODELS = [
    "deepseek-r1:7b",
    "deepseek-r1:14b",
    "deepseek-r1:32b",
    "qwen2.5:7b",
    "qwen2.5:14b",
    "llama3:8b",
]


def is_linux_path(path: str) -> bool:

    return path.startswith('/')


def get_all_samples(binary_dir: str) -> List[str]:

    trace_dir = Path(__file__).parent / "binary_trace"

    skip_binary_check = is_linux_path(binary_dir)
    if skip_binary_check:
        print(f"[*] Using Linux binary path: {binary_dir}")
        print(f"[*] Skipping local binary existence check (files are on CAPE VMs)")

    binary_path = Path(binary_dir) if not skip_binary_check else None

    samples = []
    if trace_dir.exists():
        for d in trace_dir.iterdir():
            if d.is_dir() and len(d.name) == 64:
                if skip_binary_check:
                    samples.append(d.name)
                elif (binary_path / f"{d.name}.exe").exists():
                    samples.append(d.name)

    samples.sort()
    return samples


def list_samples(binary_dir: str, start_index: int = 0, end_index: int = None):

    samples = get_all_samples(binary_dir)
    end_idx = end_index if end_index is not None else len(samples)

    print(f"\nTotal samples available: {len(samples)}")
    print("=" * 80)
    print(f"{'Index':<8} {'SHA256':<64}")
    print("-" * 80)

    for i in range(start_index, min(end_idx, len(samples))):
        print(f"{i:<8} {samples[i]}")

    print("-" * 80)
    print(f"\nShowing indices {start_index} to {min(end_idx, len(samples)) - 1}")


def get_output_dir(base_dir: str, model: str, run_name: str) -> str:

    model_dir = model.replace(":", "_").replace("/", "_")
    return str(Path(base_dir) / model_dir / run_name)


def build_command(
    run_name: str,
    binary_dir: str,
    model: str,
    llm_type: str,
    vm_hosts: str,
    output_dir: str,
    start_index: int = None,
    end_index: int = None,
    sha256: str = None,
    no_skip: bool = True,
    skip_failed_baseline: bool = False,
    parallel_baseline: bool = False
) -> List[str]:

    cmd = [
        sys.executable,
        str(Path(__file__).parent / "run_ablation.py"),
        "--run", run_name,
        "--binary-dir", binary_dir,
        "--model", model,
        "--llm-type", llm_type,
        "--vm-hosts", vm_hosts,
        "--output-dir", output_dir,
    ]

    if sha256:
        cmd.extend(["--sha256", sha256])
    else:
        if start_index is not None:
            cmd.extend(["--start-index", str(start_index)])
        if end_index is not None:
            cmd.extend(["--end-index", str(end_index)])

    if no_skip:
        cmd.append("--no-skip")

    if skip_failed_baseline:
        cmd.append("--skip-failed-baseline")

    if parallel_baseline:
        cmd.append("--parallel-baseline")

    return cmd


def run_command(cmd: List[str], dry_run: bool = False) -> bool:

    cmd_str = " ".join(cmd)

    print(f"\n{'[DRY-RUN] ' if dry_run else ''}Running command:")
    print(f"  {cmd_str}")
    print()

    if dry_run:
        return True

    try:
        result = subprocess.run(cmd, cwd=str(Path(__file__).parent))
        return result.returncode == 0
    except Exception as e:
        print(f"Error running command: {e}")
        return False


def update_global_memory(ablation_dir: str, provider: str = "openai") -> bool:

    print(f"\n{'='*60}")
    print("[GlobalMemory] Updating global memory with new results...")
    print(f"{'='*60}")

    cmd = [
        sys.executable,
        str(Path(__file__).parent / "generate_global_memory.py"),
        "--ablation-dir", ablation_dir,
        "--provider", provider,
        "--update"
    ]

    try:
        result = subprocess.run(cmd, cwd=str(Path(__file__).parent))
        if result.returncode == 0:
            print("[GlobalMemory] Update completed successfully")
            return True
        else:
            print("[GlobalMemory] Update failed")
            return False
    except Exception as e:
        print(f"[GlobalMemory] Error: {e}")
        return False


def run_analysis(output_dir: str, run_name: str):

    results_dir = Path(output_dir) / run_name

    if not results_dir.exists():
        print(f"Results directory not found: {results_dir}")
        return

    cmd = [
        sys.executable,
        str(Path(__file__).parent / "analyze_ablation_results.py"),
        "--results-dir", str(results_dir),
        "--generate-rerun"
    ]

    print(f"\n{'='*60}")
    print(f"Analyzing results for: {results_dir}")
    print(f"{'='*60}")

    subprocess.run(cmd, cwd=str(Path(__file__).parent))


def save_experiment_config(
    output_dir: str,
    models: List[str],
    runs: List[str],
    start_index: int,
    end_index: int,
    samples: List[str]
):

    config = {
        "timestamp": datetime.now().isoformat(),
        "models": models,
        "runs": runs,
        "start_index": start_index,
        "end_index": end_index,
        "num_samples": len(samples),
        "samples": [s[:16] for s in samples],
        "combinations": [
            {"model": m, "run": r}
            for m in models
            for r in runs
        ]
    }

    config_file = Path(output_dir) / "experiment_config.json"
    config_file.parent.mkdir(parents=True, exist_ok=True)

    with open(config_file, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2)

    print(f"Experiment config saved to: {config_file}")


def print_experiment_matrix(models: List[str], runs: List[str], num_samples: int):

    print("\n" + "=" * 70)
    print("EXPERIMENT MATRIX")
    print("=" * 70)
    print(f"\nModels ({len(models)}): {', '.join(models)}")
    print(f"Runs ({len(runs)}): {', '.join(runs)}")
    print(f"Samples: {num_samples}")
    print(f"\nTotal combinations: {len(models) * len(runs)}")
    print(f"Total experiment runs: {len(models) * len(runs) * num_samples}")
    print()

    print(f"{'Model':<25} | " + " | ".join([f"{r:<12}" for r in runs]))
    print("-" * (25 + 3 + len(runs) * 15))

    for model in models:
        row = f"{model:<25} | "
        row += " | ".join([f"{'[TO RUN]':<12}" for _ in runs])
        print(row)

    print()


def main():
    parser = argparse.ArgumentParser(
        description="Comprehensive ablation experiment runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run_ablation_experiment.py --start-index 0 --end-index 50 --models deepseek-r1:7b,deepseek-r1:14b

  python run_ablation_experiment.py --start-index 0 --end-index 50 --models deepseek-r1:7b

  python run_ablation_experiment.py --run Iter --models deepseek-r1:7b --start-index 0 --end-index 50

  python run_ablation_experiment.py --start-index 0 --end-index 10 --models deepseek-r1:7b,deepseek-r1:14b --dry-run

  python run_ablation_experiment.py --list-models

Tables generated after experiments:
  - Table 1: Prompt Strategy Comparison (V0 vs V1 vs V2 vs V3)
  - Table 2: PE2 Contribution (Iter vs Iter+PE2)
  - Table 3: Model Comparison (7B vs 14B vs 32B)
  - Table 4: Detailed Breakdown (iterations, signatures, etc.)
        """
    )

    parser.add_argument("--run", type=str, default="all",
                        help="Which ablation to run: all, both, NoIter, Iter, Iter+PE2, or comma-separated (default: all)")

    parser.add_argument("--models", type=str, default=",".join(DEFAULT_MODELS),
                        help=f"Comma-separated list of models (default: {','.join(DEFAULT_MODELS)})")

    parser.add_argument("--start-index", type=int, default=0,
                        help="Start index for samples (0-based, inclusive)")
    parser.add_argument("--end-index", type=int,
                        help="End index for samples (exclusive)")
    parser.add_argument("--sha256", type=str,
                        help="Run specific sample by SHA256")

    parser.add_argument("--binary-dir", type=str, default=DEFAULT_BINARY_DIR,
                        help=f"Binary directory (default: {DEFAULT_BINARY_DIR})")
    parser.add_argument("--output-dir", type=str, default="ablation_results",
                        help="Base output directory (default: ablation_results)")
    parser.add_argument("--vm-hosts", type=str, default=DEFAULT_VM_HOSTS,
                        help="Comma-separated VM hosts")
    parser.add_argument("--llm-type", type=str, default=DEFAULT_LLM_TYPE,
                        help=f"LLM type (default: {DEFAULT_LLM_TYPE})")

    parser.add_argument("--no-skip", action="store_true", default=True,
                        help="Don't skip completed samples (default: True)")
    parser.add_argument("--skip-completed", action="store_true",
                        help="Skip already completed samples")
    parser.add_argument("--skip-failed-baseline", action="store_true",
                        help="Also skip samples with 0/failed baseline signatures (use with --skip-completed)")
    parser.add_argument("--parallel-baseline", action="store_true",
                        help="Run baseline on ALL VMs in parallel and pick result with most signatures")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print commands without running")
    parser.add_argument("--analyze", action="store_true",
                        help="Run analysis after experiments complete")

    parser.add_argument("--use-global-memory", action="store_true",
                        help="Use global memory prompt (auto-loaded from memory/global_memory_prompt.txt)")
    parser.add_argument("--update-memory-every", type=int, default=0, metavar="N",
                        help="Update global memory every N completed samples (0 = disabled)")
    parser.add_argument("--memory-provider", type=str, default="openai",
                        choices=["openai", "anthropic"],
                        help="LLM provider for global memory updates (default: openai)")

    parser.add_argument("--list-samples", action="store_true",
                        help="List samples at specified indices")
    parser.add_argument("--list-models", action="store_true",
                        help="List available models")

    parser.add_argument("--continue-failed", action="store_true",
                        help="Continue only failed cases from previous runs (uses continue_iterations.py)")
    parser.add_argument("--extra-iterations", type=int, default=5,
                        help="Extra iterations to run for failed cases (default: 5)")

    args = parser.parse_args()

    if args.list_models:
        print("\nAvailable models:")
        for m in AVAILABLE_MODELS:
            print(f"  - {m}")
        print(f"\nUsage: --models {','.join(AVAILABLE_MODELS[:2])}")
        return

    if args.list_samples:
        list_samples(args.binary_dir, args.start_index, args.end_index)
        return

    if args.continue_failed:
        print("\n" + "=" * 70)
        print("CONTINUE FAILED CASES")
        print("=" * 70)
        print(f"\nThis will continue ONLY failed cases with {args.extra_iterations} extra iterations.")
        print("Successful cases (even at early iterations) will be SKIPPED.\n")

        cmd = [
            sys.executable,
            str(Path(__file__).parent / "continue_iterations.py"),
            "--ablation-dir", args.output_dir,
            "--continue",
            "--extra-iterations", str(args.extra_iterations),
            "--vm-hosts", args.vm_hosts,
            "--binary-dir", args.binary_dir,
        ]

        if args.dry_run:
            cmd.append("--dry-run")
            print(f"[DRY-RUN] Would run: {' '.join(cmd)}")
        else:
            print(f"Running: {' '.join(cmd)}\n")
            result = subprocess.run(cmd, cwd=str(Path(__file__).parent))
            if result.returncode != 0:
                print("[!] Continue failed cases command failed")
                return

        return

    models = [m.strip() for m in args.models.split(",")]

    run_input = args.run.lower().strip()
    if run_input == "all":
        runs = ["NoIter", "Iter", "Iter+PE2"]
    elif run_input == "both":
        runs = ["Iter", "Iter+PE2"]
    elif "," in args.run:
        runs = []
        for r in args.run.split(","):
            r = r.strip()
            if r.lower() == "iter":
                runs.append("Iter")
            elif r.lower() in ["iter+pe2", "iter+pe"]:
                runs.append("Iter+PE2")
            elif r.lower() == "noiter":
                runs.append("NoIter")
            else:
                runs.append(r)
    else:
        if run_input == "iter":
            runs = ["Iter"]
        elif run_input in ["iter+pe2", "iter+pe"]:
            runs = ["Iter+PE2"]
        elif run_input == "noiter":
            runs = ["NoIter"]
        else:
            runs = [args.run]

    no_skip = not args.skip_completed

    all_samples = get_all_samples(args.binary_dir)
    end_idx = args.end_index if args.end_index else len(all_samples)
    selected_samples = all_samples[args.start_index:end_idx]

    if not selected_samples and not args.sha256:
        print("ERROR: No samples found!")
        return

    print("=" * 70)
    print("COMPREHENSIVE ABLATION EXPERIMENT")
    print("=" * 70)
    print(f"\nModels: {', '.join(models)}")
    print(f"Runs: {', '.join(runs)}")
    print(f"LLM Type: {args.llm_type}")
    print(f"Binary Dir: {args.binary_dir}")
    print(f"Output Dir: {args.output_dir}")
    print(f"VM Hosts: {args.vm_hosts}")

    if args.sha256:
        print(f"Sample: {args.sha256}")
        num_samples = 1
    else:
        print(f"Index Range: [{args.start_index}:{end_idx}]")
        print(f"Samples: {len(selected_samples)}")
        num_samples = len(selected_samples)

    print(f"Skip completed: {not no_skip}")
    print(f"Dry run: {args.dry_run}")

    if args.use_global_memory or args.update_memory_every > 0:
        print(f"\n[GlobalMemory] Settings:")
        print(f"  Use global memory: {args.use_global_memory}")
        if args.update_memory_every > 0:
            print(f"  Update every: {args.update_memory_every} samples")
            print(f"  Provider: {args.memory_provider}")

    print_experiment_matrix(models, runs, num_samples)

    if not args.dry_run:
        save_experiment_config(
            args.output_dir, models, runs,
            args.start_index, end_idx, selected_samples
        )

    total_combinations = len(models) * len(runs)
    current = 0
    success = True
    results_dirs = []

    for model in models:
        for run_name in runs:
            current += 1
            print(f"\n{'='*70}")
            print(f"[{current}/{total_combinations}] Model: {model}, Run: {run_name}")
            print(f"{'='*70}")

            output_subdir = get_output_dir(args.output_dir, model, run_name)
            results_dirs.append((model, run_name, output_subdir))

            cmd = build_command(
                run_name=run_name,
                binary_dir=args.binary_dir,
                model=model,
                llm_type=args.llm_type,
                vm_hosts=args.vm_hosts,
                output_dir=output_subdir,
                start_index=args.start_index if not args.sha256 else None,
                end_index=args.end_index if not args.sha256 else None,
                sha256=args.sha256,
                no_skip=no_skip,
                skip_failed_baseline=args.skip_failed_baseline,
                parallel_baseline=args.parallel_baseline
            )

            if not run_command(cmd, args.dry_run):
                print(f"\nERROR: {model} / {run_name} failed!")
                success = False
                continue

            if args.update_memory_every > 0 and not args.dry_run:
                update_global_memory(args.output_dir, args.memory_provider)

    if args.analyze and success and not args.dry_run:
        print("\n" + "=" * 70)
        print("RUNNING ANALYSIS")
        print("=" * 70)

        for model, run_name, output_dir in results_dirs:
            run_analysis(output_dir, run_name)

    if args.update_memory_every > 0 and not args.dry_run:
        print("\n" + "=" * 70)
        print("[GlobalMemory] Final update after all experiments...")
        update_global_memory(args.output_dir, args.memory_provider)

    print("\n" + "=" * 70)
    print("EXPERIMENT SUMMARY")
    print("=" * 70)

    if args.dry_run:
        print("\n[DRY-RUN] No experiments were executed.")
        print(f"Would run {total_combinations} combinations:")
    else:
        print(f"\nCompleted {total_combinations} combinations:")

    for model, run_name, output_dir in results_dirs:
        print(f"  - {model} / {run_name} -> {output_dir}")

    print("\n" + "-" * 70)
    print("NEXT STEPS:")
    print("-" * 70)
    print("\n1. Compare Iter vs Iter+PE2 (per model):")
    for model in models:
        model_dir = model.replace(":", "_").replace("/", "_")
        print(f"   python compare_ablation_runs.py --results-dir {args.output_dir}/{model_dir}")

    print("\n2. Generate paper tables:")
    print(f"   python generate_paper_tables.py --results-dir {args.output_dir}")

    print("\n3. Analyze individual runs:")
    for model, run_name, output_dir in results_dirs:
        print(f"   python analyze_ablation_results.py --results-dir {output_dir}")


if __name__ == "__main__":
    main()
