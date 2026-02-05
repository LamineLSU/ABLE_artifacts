
from dataclasses import dataclass, field
from typing import List, Optional, Dict
from enum import Enum


class PromptStrategy(Enum):

    V0_ZEROSHOT = "v0"
    V1_COT = "v1"
    V2_COUNTERFACTUAL = "v2"
    V3_ADVERSARIAL = "v3"


class EvolutionMode(Enum):

    NONE = "none"
    RULE_ONLY = "rule_only"
    PROMPT_SAMPLE = "prompt_sample"
    PROMPT_BATCH = "prompt_batch"
    FULL_HYBRID = "full_hybrid"


@dataclass
class AblationConfig:


    name: str
    description: str

    prompt_strategy: PromptStrategy

    evolution_mode: EvolutionMode
    max_rule_iterations: int = 1
    max_prompt_iterations: int = 1
    batch_size_for_prompt_update: int = 10

    pe2_step_size: int = 50
    pe2_max_prompt_length: int = 500
    pe2_use_history: bool = True

    min_signature_improvement: int = 1
    early_stop_on_success: bool = True

    def to_dict(self) -> Dict:
        return {
            'name': self.name,
            'description': self.description,
            'prompt_strategy': self.prompt_strategy.value,
            'evolution_mode': self.evolution_mode.value,
            'max_rule_iterations': self.max_rule_iterations,
            'max_prompt_iterations': self.max_prompt_iterations,
            'batch_size_for_prompt_update': self.batch_size_for_prompt_update,
            'pe2_step_size': self.pe2_step_size,
            'pe2_max_prompt_length': self.pe2_max_prompt_length,
            'pe2_use_history': self.pe2_use_history,
            'min_signature_improvement': self.min_signature_improvement,
            'early_stop_on_success': self.early_stop_on_success
        }


ABLATION_PROMPT_STRATEGY = [
    AblationConfig(
        name="V0_baseline",
        description="Zero-shot baseline - no reasoning guidance",
        prompt_strategy=PromptStrategy.V0_ZEROSHOT,
        evolution_mode=EvolutionMode.NONE,
        max_rule_iterations=1,
    ),
    AblationConfig(
        name="V1_cot",
        description="Chain-of-Thought - step by step reasoning",
        prompt_strategy=PromptStrategy.V1_COT,
        evolution_mode=EvolutionMode.NONE,
        max_rule_iterations=1,
    ),
    AblationConfig(
        name="V2_counterfactual",
        description="Counterfactual reasoning - what-if analysis",
        prompt_strategy=PromptStrategy.V2_COUNTERFACTUAL,
        evolution_mode=EvolutionMode.NONE,
        max_rule_iterations=1,
    ),
    AblationConfig(
        name="V3_adversarial",
        description="Adversarial reasoning - attacker/defender perspective",
        prompt_strategy=PromptStrategy.V3_ADVERSARIAL,
        evolution_mode=EvolutionMode.NONE,
        max_rule_iterations=1,
    ),
]

ABLATION_RULE_ITERATION = [
    AblationConfig(
        name="V1_iter1",
        description="CoT with 1 iteration (no rule evolution)",
        prompt_strategy=PromptStrategy.V1_COT,
        evolution_mode=EvolutionMode.NONE,
        max_rule_iterations=1,
    ),
    AblationConfig(
        name="V1_iter3",
        description="CoT with 3 rule evolution iterations",
        prompt_strategy=PromptStrategy.V1_COT,
        evolution_mode=EvolutionMode.RULE_ONLY,
        max_rule_iterations=3,
    ),
    AblationConfig(
        name="V1_iter5",
        description="CoT with 5 rule evolution iterations",
        prompt_strategy=PromptStrategy.V1_COT,
        evolution_mode=EvolutionMode.RULE_ONLY,
        max_rule_iterations=5,
    ),
]

ABLATION_PROMPT_EVOLUTION = [
    AblationConfig(
        name="V1_rule_only",
        description="Rule evolution only, fixed prompt",
        prompt_strategy=PromptStrategy.V1_COT,
        evolution_mode=EvolutionMode.RULE_ONLY,
        max_rule_iterations=3,
        max_prompt_iterations=1,
    ),
    AblationConfig(
        name="V1_pe2_sample",
        description="PE2 per-sample prompt evolution",
        prompt_strategy=PromptStrategy.V1_COT,
        evolution_mode=EvolutionMode.PROMPT_SAMPLE,
        max_rule_iterations=3,
        max_prompt_iterations=3,
    ),
    AblationConfig(
        name="V1_pe2_batch",
        description="PE2 batch-level prompt evolution (after every 10 samples)",
        prompt_strategy=PromptStrategy.V1_COT,
        evolution_mode=EvolutionMode.PROMPT_BATCH,
        max_rule_iterations=3,
        max_prompt_iterations=1,
        batch_size_for_prompt_update=10,
    ),
    AblationConfig(
        name="V1_pe2_hybrid",
        description="Full hybrid: rule + sample PE2 + batch PE2",
        prompt_strategy=PromptStrategy.V1_COT,
        evolution_mode=EvolutionMode.FULL_HYBRID,
        max_rule_iterations=3,
        max_prompt_iterations=3,
        batch_size_for_prompt_update=10,
    ),
]

FULL_ABLATION_MATRIX = []

for prompt_strategy in PromptStrategy:
    for evolution_mode in [EvolutionMode.NONE, EvolutionMode.RULE_ONLY, EvolutionMode.FULL_HYBRID]:
        max_rule_iter = 1 if evolution_mode == EvolutionMode.NONE else 3
        max_prompt_iter = 3 if evolution_mode == EvolutionMode.FULL_HYBRID else 1

        FULL_ABLATION_MATRIX.append(AblationConfig(
            name=f"{prompt_strategy.value}_{evolution_mode.value}",
            description=f"{prompt_strategy.name} with {evolution_mode.name}",
            prompt_strategy=prompt_strategy,
            evolution_mode=evolution_mode,
            max_rule_iterations=max_rule_iter,
            max_prompt_iterations=max_prompt_iter,
        ))


def get_ablation_configs(ablation_type: str) -> List[AblationConfig]:

    if ablation_type == 'prompt':
        return ABLATION_PROMPT_STRATEGY
    elif ablation_type == 'iteration':
        return ABLATION_RULE_ITERATION
    elif ablation_type == 'evolution':
        return ABLATION_PROMPT_EVOLUTION
    elif ablation_type == 'full':
        return FULL_ABLATION_MATRIX
    else:
        raise ValueError(f"Unknown ablation type: {ablation_type}")


def get_config_by_name(name: str) -> Optional[AblationConfig]:

    all_configs = (
        ABLATION_PROMPT_STRATEGY +
        ABLATION_RULE_ITERATION +
        ABLATION_PROMPT_EVOLUTION +
        FULL_ABLATION_MATRIX
    )
    for config in all_configs:
        if config.name == name:
            return config
    return None


def print_ablation_summary():

    print("=" * 80)
    print("ABLATION EXPERIMENT CONFIGURATIONS")
    print("=" * 80)

    print("\n## Ablation 1: Prompt Strategy (RQ1)")
    print("-" * 60)
    for cfg in ABLATION_PROMPT_STRATEGY:
        print(f"  {cfg.name:<20} | {cfg.prompt_strategy.value} | {cfg.description}")

    print("\n## Ablation 2: Rule Iteration (RQ2)")
    print("-" * 60)
    for cfg in ABLATION_RULE_ITERATION:
        print(f"  {cfg.name:<20} | iter={cfg.max_rule_iterations} | {cfg.description}")

    print("\n## Ablation 3: Prompt Evolution (RQ3)")
    print("-" * 60)
    for cfg in ABLATION_PROMPT_EVOLUTION:
        print(f"  {cfg.name:<20} | {cfg.evolution_mode.value} | {cfg.description}")

    print("\n## Full Matrix")
    print("-" * 60)
    print(f"  Total configurations: {len(FULL_ABLATION_MATRIX)}")


if __name__ == "__main__":
    print_ablation_summary()