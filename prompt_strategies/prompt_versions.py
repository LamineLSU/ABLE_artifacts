
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

from . import v1_simple
from . import v2_counterfactual
from . import v3_adversarial
from . import v4_pattern_decomposition
from . import v5_evolutionary
from . import v6_hybrid
from . import v7_optimal
from . import v8_adaptive_counterfactual
from . import v9_counterfactual_wildcards
from . import v10_adversarial_dual


@dataclass
class PromptMetadata:

    version: str
    name: str
    accuracy: float
    validation_samples: int
    speed: str
    use_case: str
    description: str


PROMPT_MODULES = {
    "v1": v1_simple,
    "v2": v2_counterfactual,
    "v3": v3_adversarial,
    "v4": v4_pattern_decomposition,
    "v5": v5_evolutionary,
    "v6": v6_hybrid,
    "v7": v7_optimal,
    "v8": v8_adaptive_counterfactual,
    "v9": v9_counterfactual_wildcards,
    "v10": v10_adversarial_dual,
}

RECOMMENDED_PROMPT = "v7"

ALL_PROMPTS: Dict[str, str] = {
    version: module.PROMPT for version, module in PROMPT_MODULES.items()
}

PROMPT_METADATA: Dict[str, PromptMetadata] = {
    version: PromptMetadata(**module.METADATA)
    for version, module in PROMPT_MODULES.items()
}

PROMPT_V1_SIMPLE = v1_simple.PROMPT
PROMPT_V2_COUNTERFACTUAL = v2_counterfactual.PROMPT
PROMPT_V3_ADVERSARIAL = v3_adversarial.PROMPT
PROMPT_V4_PATTERN_DECOMPOSITION = v4_pattern_decomposition.PROMPT
PROMPT_V5_EVOLUTIONARY = v5_evolutionary.PROMPT
PROMPT_V6_HYBRID = v6_hybrid.PROMPT
PROMPT_V7_OPTIMAL = v7_optimal.PROMPT
PROMPT_V8_ADAPTIVE_COUNTERFACTUAL = v8_adaptive_counterfactual.PROMPT
PROMPT_V9_COUNTERFACTUAL_WILDCARDS = v9_counterfactual_wildcards.PROMPT
PROMPT_V10_ADVERSARIAL_DUAL = v10_adversarial_dual.PROMPT


def get_prompt(version: str) -> str:

    if version.lower() == "recommended":
        version = RECOMMENDED_PROMPT

    version = version.lower()
    if version not in ALL_PROMPTS:
        raise ValueError(f"Unknown prompt version: {version}. Available: {list(ALL_PROMPTS.keys())}")

    return ALL_PROMPTS[version]


def list_prompts() -> List[str]:

    return list(ALL_PROMPTS.keys())


def get_prompt_metadata(version: str) -> PromptMetadata:

    version = version.lower()
    if version not in PROMPT_METADATA:
        raise ValueError(f"Unknown prompt version: {version}")

    return PROMPT_METADATA[version]


def get_all_prompts_for_evaluation() -> List[Tuple[str, str, PromptMetadata]]:

    return [(v, p, PROMPT_METADATA[v]) for v, p in ALL_PROMPTS.items()]


def format_prompt(version: str, trace: str) -> str:

    template = get_prompt(version)
    return template.format(trace=trace)


def get_prompt_summary() -> str:

    lines = [
        "Prompt Version Summary",
        "=" * 70,
        f"{'Version':<8} {'Name':<30} {'Accuracy':<10} {'Speed':<8} {'Samples':<8}",
        "-" * 70,
    ]
    for version, meta in PROMPT_METADATA.items():
        rec = " ⭐" if version == RECOMMENDED_PROMPT else ""
        lines.append(
            f"{version:<8} {meta.name:<30} {meta.accuracy*100:>6.0f}%    {meta.speed:<8} {meta.validation_samples:<8}{rec}"
        )
    lines.append("-" * 70)
    lines.append(f"Recommended: {RECOMMENDED_PROMPT}")
    return "\n".join(lines)