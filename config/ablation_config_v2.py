
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional


PROMPT_VERSIONS = ["v0", "v1", "v2", "v3"]


@dataclass
class AblationRun:

    name: str
    prompts: List[str]
    iteration: bool = True
    pe2: bool = False
    max_iterations: int = 3
    retry_on_error: bool = True
    max_retries: int = 3
    use_retry_feedback: bool = True
    description: str = ""

    def __post_init__(self):
        if self.pe2 and not self.iteration:
            raise ValueError("PE2 requires Iteration to be enabled (needs failure feedback)")

    def to_dict(self) -> Dict:
        return {
            'name': self.name,
            'prompts': self.prompts,
            'iteration': self.iteration,
            'pe2': self.pe2,
            'max_iterations': self.max_iterations if self.iteration else 1,
            'retry_on_error': self.retry_on_error,
            'max_retries': self.max_retries,
            'use_retry_feedback': self.use_retry_feedback,
            'description': self.description
        }

    def get_cli_args(self, sha256: str, binary_path: str, vm_hosts: List[str],
                     llm_type: str = "ollama", model: str = "deepseek-r1:7b") -> List[str]:

        args = [
            "--sha256", sha256,
            "--binary", binary_path,
            "--prompts", ",".join(self.prompts),
            "--max-iterations", str(self.max_iterations),
            "--llm-type", llm_type,
            "--model", model,
            "--vm-hosts", ",".join(vm_hosts),
        ]

        if self.iteration:
            args.append("--evolving")

        if self.pe2:
            args.append("--pe2")

        if self.retry_on_error:
            args.extend(["--max-retries", str(self.max_retries)])
            if self.use_retry_feedback:
                args.append("--retry-feedback")
        else:
            args.append("--no-retry")

        return args


ABLATION_RUNS = [
    AblationRun(
        name="NoIter",
        prompts=["v0", "v1", "v2", "v3"],
        iteration=False,
        pe2=False,
        max_iterations=1,
        description="Single-shot baseline (no iteration)"
    ),

    AblationRun(
        name="Iter",
        prompts=["v0", "v1", "v2", "v3"],
        iteration=True,
        pe2=False,
        max_iterations=3,
        description="With iteration, no PE2"
    ),

    AblationRun(
        name="Iter+PE2",
        prompts=["v0", "v1", "v2", "v3"],
        iteration=True,
        pe2=True,
        max_iterations=3,
        description="Full system (iteration + PE2)"
    ),
]


def load_prompt_template(prompt_version: str) -> str:

    prompt_dir = Path(__file__).parent.parent / "prompt_strategies"

    version_files = {
        'v0': 'v0_zeroshot.md',
        'v1': 'v1_simple.md',
        'v2': 'v2_counterfactual.md',
        'v3': 'v3_adversarial.md',
    }

    filename = version_files.get(prompt_version.lower())
    if not filename:
        raise ValueError(f"Unknown prompt version: {prompt_version}. Use v0, v1, v2, or v3.")

    filepath = prompt_dir / filename
    if not filepath.exists():
        raise FileNotFoundError(f"Prompt file not found: {filepath}")

    content = filepath.read_text(encoding='utf-8')

    if content.startswith('---'):
        parts = content.split('---', 2)
        if len(parts) >= 3:
            content = parts[2].strip()

    return content


def get_prompt_for_run(run: AblationRun, prompt_version: str) -> str:

    return load_prompt_template(prompt_version)


def print_ablation_table():

    print("=" * 90)
    print("ABLATION EXPERIMENT RUNS")
    print("=" * 90)
    print()
    print(f"{'#':<3} {'Run Name':<15} {'Prompts':<20} {'Iter':<6} {'PE2':<5} {'MaxIter':<8} Description")
    print("-" * 90)

    for i, run in enumerate(ABLATION_RUNS, 1):
        prompts_str = ",".join(run.prompts)
        print(f"{i:<3} {run.name:<15} "
              f"{prompts_str:<20} "
              f"{'Yes' if run.iteration else 'No':<6} "
              f"{'Yes' if run.pe2 else 'No':<5} "
              f"{run.max_iterations:<8} "
              f"{run.description[:25]}...")

    print("-" * 90)
    print()
    print("Each run processes all 4 prompts (V0-V3) in parallel on 4 VMs.")
    print()
    print("Results obtained:")
    print("  Run 1 (Iter):      V0+Iter, V1+Iter, V2+Iter, V3+Iter")
    print("                     + derived @iter1 for each (iteration contribution)")
    print("  Run 2 (Iter+PE2):  V0+Iter+PE2, V1+Iter+PE2, V2+Iter+PE2, V3+Iter+PE2")
    print()
    print("Ablation analysis:")
    print("  - Prompt comparison: Compare V0 vs V1 vs V2 vs V3 (same run = fair)")
    print("  - Iteration effect:  V3+Iter - V3@iter1")
    print("  - PE2 effect:        V3+Iter+PE2 - V3+Iter")


def get_run_by_name(name: str) -> Optional[AblationRun]:

    for run in ABLATION_RUNS:
        if run.name == name:
            return run
    return None


def calculate_feature_contribution(results: Dict[str, float]) -> Dict[str, float]:

    contributions = {}

    full = results.get('v3+Iter+PE2', 0)

    if 'v3+Iter' in results:
        contributions['PE2'] = full - results['v3+Iter']

    if 'v3+Iter' in results and 'v3@iter1' in results:
        contributions['Iteration'] = results['v3+Iter'] - results['v3@iter1']

    if 'v3+Iter' in results and 'v2+Iter' in results:
        contributions['V3 vs V2'] = results['v3+Iter'] - results['v2+Iter']

    if 'v3+Iter' in results and 'v1+Iter' in results:
        contributions['V3 vs V1'] = results['v3+Iter'] - results['v1+Iter']

    if 'v3+Iter' in results and 'v0+Iter' in results:
        contributions['V3 vs V0'] = results['v3+Iter'] - results['v0+Iter']

    if 'v0@iter1' in results:
        contributions['Total (vs baseline)'] = full - results['v0@iter1']

    return contributions


if __name__ == "__main__":
    print_ablation_table()

    print("\n\nExample CLI commands:\n")
    for run in ABLATION_RUNS:
        args = run.get_cli_args(
            sha256="<SHA256>",
            binary_path="<BINARY_PATH>",
            vm_hosts=["192.168.197.146", "192.168.197.147", "192.168.197.148", "192.168.197.141"]
        )
        print(f"Run '{run.name}':")
        print(f"  python simplified_bypass_pipeline.py {' '.join(args)}")
        print()
