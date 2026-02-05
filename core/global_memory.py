
import json
import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
import logging

logger = logging.getLogger(__name__)


@dataclass
class IterationOutcome:

    sample_sha256: str
    model_name: str
    prompt_version: str
    iteration_number: int
    success: bool
    rule_hit: bool
    new_signatures: int
    feedback: str
    pattern_type: Optional[str] = None
    confidence: Optional[int] = None
    yara_rule: Optional[str] = None
    trace_snippet: Optional[str] = None
    reasoning: Optional[str] = None


@dataclass
class AblationResultsSummary:

    total_samples: int = 0
    total_iterations: int = 0
    successful_samples: int = 0

    hit_no_sig_cases: List[IterationOutcome] = field(default_factory=list)
    crash_cases: List[IterationOutcome] = field(default_factory=list)
    success_cases: List[IterationOutcome] = field(default_factory=list)
    no_hit_cases: List[IterationOutcome] = field(default_factory=list)

    recovery_patterns: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class ProcessedState:

    processed_samples: Dict[str, List[str]] = field(default_factory=dict)
    last_update: str = ""
    version: int = 1

    def add_sample(self, model: str, sha256: str) -> None:
        if model not in self.processed_samples:
            self.processed_samples[model] = []
        if sha256 not in self.processed_samples[model]:
            self.processed_samples[model].append(sha256)

    def is_processed(self, model: str, sha256: str) -> bool:
        return sha256 in self.processed_samples.get(model, [])

    def get_total_processed(self) -> int:
        return sum(len(samples) for samples in self.processed_samples.values())


class AblationResultsCollector:


    def __init__(self, ablation_base_dir: Path):
        self.ablation_base_dir = Path(ablation_base_dir)

    def collect_all_results(
        self,
        processed_state: Optional[ProcessedState] = None,
        only_new: bool = False
    ) -> Tuple[AblationResultsSummary, ProcessedState]:

        summary = AblationResultsSummary()
        state = processed_state or ProcessedState()

        model_dirs = [
            d for d in self.ablation_base_dir.iterdir()
            if d.is_dir() and not d.name.startswith('.')
            and (d / 'Iter' / 'Iter').exists()
        ]

        for model_dir in model_dirs:
            model_name = model_dir.name
            self._collect_model_results(
                model_dir, model_name, summary,
                state=state, only_new=only_new
            )

        from datetime import datetime
        state.last_update = datetime.now().isoformat()

        return summary, state

    def _collect_model_results(
        self,
        model_dir: Path,
        model_name: str,
        summary: AblationResultsSummary,
        state: Optional[ProcessedState] = None,
        only_new: bool = False
    ) -> None:

        iter_dir = model_dir / 'Iter' / 'Iter'
        if not iter_dir.exists():
            return

        for sample_dir in iter_dir.iterdir():
            if not sample_dir.is_dir():
                continue

            sample_sha256 = sample_dir.name
            if len(sample_sha256) < 16:
                continue

            if only_new and state and state.is_processed(model_name, sample_sha256):
                continue

            summary.total_samples += 1

            eval_logs_dir = sample_dir / 'evaluation_logs'
            if not eval_logs_dir.exists():
                continue

            eval_subdirs = sorted(
                eval_logs_dir.glob(f"{sample_sha256}_*"),
                reverse=True
            )
            if not eval_subdirs:
                continue

            latest_eval = eval_subdirs[0]

            for strategy_file in latest_eval.glob('strategy_v*.json'):
                self._process_strategy_file(
                    strategy_file,
                    sample_sha256,
                    model_name,
                    summary
                )

            if state:
                state.add_sample(model_name, sample_sha256)

    def _process_strategy_file(
        self,
        strategy_file: Path,
        sample_sha256: str,
        model_name: str,
        summary: AblationResultsSummary
    ) -> None:

        try:
            with open(strategy_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except Exception as e:
            logger.warning(f"Failed to read {strategy_file}: {e}")
            return

        prompt_version = data.get('prompt_version', 'unknown')
        iterations = data.get('iterations', [])

        if data.get('success'):
            summary.successful_samples += 1

        previous_outcome = None

        for iteration in iterations:
            summary.total_iterations += 1

            cape = iteration.get('cape_analysis') or {}
            llm = iteration.get('llm_query') or {}

            outcome = IterationOutcome(
                sample_sha256=sample_sha256,
                model_name=model_name,
                prompt_version=prompt_version,
                iteration_number=iteration.get('iteration_number', 0),
                success=iteration.get('success', False),
                rule_hit=cape.get('rule_hit', False),
                new_signatures=iteration.get('new_signatures', 0),
                feedback=iteration.get('feedback_given', ''),
                pattern_type=llm.get('pattern_type'),
                confidence=llm.get('confidence'),
                yara_rule=llm.get('yara_rule'),
                reasoning=llm.get('response_text', '')[:500] if llm.get('response_text') else None
            )

            if outcome.success:
                summary.success_cases.append(outcome)
                if previous_outcome and not previous_outcome.success:
                    summary.recovery_patterns.append({
                        'failed': previous_outcome,
                        'succeeded': outcome,
                        'sample': sample_sha256,
                        'model': model_name
                    })
            elif outcome.rule_hit and outcome.new_signatures == 0:
                summary.hit_no_sig_cases.append(outcome)
            elif 'crash' in outcome.feedback.lower() or 'error' in outcome.feedback.lower():
                summary.crash_cases.append(outcome)
            else:
                summary.no_hit_cases.append(outcome)

            previous_outcome = outcome


class InsightExtractor:


    INSIGHT_EXTRACTION_PROMPT = """You are a malware analysis expert analyzing YARA bypass rule generation experiments.

We generate YARA rules to bypass malware sandbox evasion. Rules target byte patterns in execution traces
and use CAPE sandbox's breakpoint system (cape_options meta field) to skip evasion checks.

A successful bypass = rule hits AND produces new behavioral signatures (malware executes further).
"Hit but no new signatures" = rule matched wrong location, bypass point ineffective.

Extract STRATEGIC insights from the data below. The output will be prepended to prompts given to
local LLMs generating bypass rules.

**CRITICAL: Output must be STRATEGIC GUIDANCE, not specific hex patterns.**
- The local LLM must analyze each trace independently
- DO NOT include specific hex byte examples (they will cause copy-paste behavior)
- Focus on WHERE in the trace to look and WHAT instruction patterns to target
- Guide the LLM's reasoning process, not give it answers


{pattern_type_stats}

These are the most valuable - showing exactly what fix worked.
{recovery_analysis}

{failure_patterns}

{success_examples}


Generate strategic guidance (200-300 words) in this exact format:

```

**WHERE to Find Bypass Points (MOST IMPORTANT):**
[Describe the LOCATION in traces where successful bypasses are found - first 30%, near conditionals, etc.]
[Describe instruction SEQUENCES to look for - e.g., "CALL followed by TEST EAX followed by conditional jump"]
[DO NOT include specific hex bytes - describe the pattern abstractly]

**When "Rule hit but no new signatures" (most common failure):**
[What LOCATION change typically fixes this - move earlier/later in trace?]
[What instruction pattern should they target instead?]

**Common Mistakes:**
[What patterns or locations tend to fail?]
[What should the LLM avoid doing?]

**Success Indicators:**
[What characteristics do successful bypass points share?]
[How can the LLM identify good candidates in a trace?]
```

IMPORTANT: Do NOT include any specific hex byte sequences. The guidance must work for ANY trace,
not just the ones in the training data. Focus on teaching the LLM HOW to find good patterns,
not WHAT specific patterns to use.
"""

    UPDATE_MEMORY_PROMPT = """You are updating an existing Global Memory with new experiment insights.

```
{existing_memory}
```


{pattern_type_stats}

{recovery_analysis}

{failure_patterns}

{success_examples}

Update the Global Memory by:
1. KEEP strategic insights that are still valid
2. ADD new strategic insights from the new data
3. REFINE existing guidance if new data provides better strategies
4. REMOVE insights that new data contradicts

**CRITICAL: Keep output STRATEGIC, not example-based.**
- DO NOT add specific hex byte patterns
- Focus on WHERE to look and WHAT instruction patterns to target
- Guide reasoning, don't give copy-paste answers

Output the COMPLETE updated Global Memory in the same format as the original.
Keep the total length similar (200-300 words). Focus on strategies, not specific patterns.
"""

    def __init__(self, api_provider: str = "anthropic", model: str = "claude-sonnet-4-20250514"):

        self.api_provider = api_provider
        self.model = model

    def _analyze_pattern_types(self, outcomes: List[IterationOutcome]) -> str:

        from collections import Counter

        success_patterns = Counter()
        failure_patterns = Counter()

        for outcome in outcomes:
            pattern = outcome.pattern_type or 'unknown'
            if outcome.success:
                success_patterns[pattern] += 1
            else:
                failure_patterns[pattern] += 1

        lines = ["Successful pattern types:"]
        for pattern, count in success_patterns.most_common(10):
            lines.append(f"  - {pattern}: {count} successes")

        lines.append("\nFailed pattern types:")
        for pattern, count in failure_patterns.most_common(10):
            lines.append(f"  - {pattern}: {count} failures")

        return "\n".join(lines)

    def _analyze_recoveries(
        self,
        recoveries: List[Dict[str, Any]],
        max_examples: int = 30
    ) -> str:

        if not recoveries:
            return "No recovery patterns found."

        by_failure_type = {}
        for recovery in recoveries[:max_examples]:
            failed = recovery['failed']
            succeeded = recovery['succeeded']
            failure_feedback = failed.feedback or 'unknown'

            if failure_feedback not in by_failure_type:
                by_failure_type[failure_feedback] = []

            by_failure_type[failure_feedback].append({
                'failed_pattern': failed.pattern_type,
                'success_pattern': succeeded.pattern_type,
                'success_reasoning': (succeeded.reasoning or '')[:400]
            })

        lines = []
        for failure_type, examples in by_failure_type.items():
            lines.append(f"\n### After '{failure_type}' failures:")
            lines.append(f"  Found {len(examples)} recovery cases. Examples:")

            for i, ex in enumerate(examples[:5]):
                lines.append(f"\n  Example {i+1}:")
                lines.append(f"    Failed pattern type: {ex['failed_pattern']}")
                lines.append(f"    Success pattern type: {ex['success_pattern']}")
                if ex['success_reasoning']:
                    lines.append(f"    What worked: {ex['success_reasoning'][:300]}...")

        return "\n".join(lines)

    def _analyze_failures(
        self,
        failures: List[IterationOutcome],
        max_examples: int = 20
    ) -> str:

        if not failures:
            return "No failure examples."

        by_feedback = {}
        for outcome in failures[:100]:
            feedback = outcome.feedback or 'unknown'
            if feedback not in by_feedback:
                by_feedback[feedback] = []
            by_feedback[feedback].append(outcome)

        lines = []
        for feedback, examples in sorted(by_feedback.items(), key=lambda x: -len(x[1])):
            lines.append(f"\n'{feedback}' - {len(examples)} cases:")

            patterns = [e.pattern_type for e in examples if e.pattern_type]
            if patterns:
                from collections import Counter
                common = Counter(patterns).most_common(3)
                lines.append(f"  Common pattern types: {common}")

            for ex in examples[:3]:
                if ex.reasoning:
                    reasoning_snippet = ex.reasoning[:150].replace('\n', ' ')
                    lines.append(f"  Reasoning: {reasoning_snippet}...")

        return "\n".join(lines)

    def _format_success_examples(
        self,
        successes: List[IterationOutcome],
        max_examples: int = 15
    ) -> str:

        if not successes:
            return "No success examples."

        seen_patterns = set()
        examples = []

        for outcome in successes:
            pattern = outcome.pattern_type or 'unknown'
            if pattern in seen_patterns and len(examples) > 5:
                continue
            seen_patterns.add(pattern)

            example_lines = [
                f"\n- Pattern type: {pattern}",
                f"  New signatures discovered: {outcome.new_signatures}",
            ]

            if outcome.reasoning:
                example_lines.append(f"  Why it worked: {outcome.reasoning[:400]}...")

            examples.append("\n".join(example_lines))

            if len(examples) >= max_examples:
                break

        return "\n".join(examples)

    def extract_insights(self, summary: AblationResultsSummary) -> str:

        all_outcomes = (
            summary.success_cases +
            summary.hit_no_sig_cases +
            summary.crash_cases +
            summary.no_hit_cases
        )

        pattern_type_stats = self._analyze_pattern_types(all_outcomes)
        recovery_analysis = self._analyze_recoveries(summary.recovery_patterns, max_examples=50)
        failure_patterns = self._analyze_failures(summary.hit_no_sig_cases, max_examples=30)
        success_examples = self._format_success_examples(summary.success_cases, max_examples=20)

        prompt = self.INSIGHT_EXTRACTION_PROMPT.format(
            pattern_type_stats=pattern_type_stats,
            recovery_analysis=recovery_analysis,
            failure_patterns=failure_patterns,
            success_examples=success_examples
        )

        if self.api_provider == "anthropic":
            return self._call_anthropic(prompt)
        elif self.api_provider == "openai":
            return self._call_openai(prompt)
        else:
            raise ValueError(f"Unknown API provider: {self.api_provider}")

    def update_insights(
        self,
        existing_memory: str,
        new_summary: AblationResultsSummary
    ) -> str:

        all_outcomes = (
            new_summary.success_cases +
            new_summary.hit_no_sig_cases +
            new_summary.crash_cases +
            new_summary.no_hit_cases
        )

        if not all_outcomes:
            logger.info("No new outcomes to analyze, keeping existing memory")
            return existing_memory

        pattern_type_stats = self._analyze_pattern_types(all_outcomes)
        recovery_analysis = self._analyze_recoveries(new_summary.recovery_patterns, max_examples=30)
        failure_patterns = self._analyze_failures(new_summary.hit_no_sig_cases, max_examples=20)
        success_examples = self._format_success_examples(new_summary.success_cases, max_examples=10)

        prompt = self.UPDATE_MEMORY_PROMPT.format(
            existing_memory=existing_memory,
            new_samples_count=new_summary.total_samples,
            pattern_type_stats=pattern_type_stats,
            recovery_analysis=recovery_analysis,
            failure_patterns=failure_patterns,
            success_examples=success_examples
        )

        if self.api_provider == "anthropic":
            return self._call_anthropic(prompt)
        elif self.api_provider == "openai":
            return self._call_openai(prompt)
        else:
            raise ValueError(f"Unknown API provider: {self.api_provider}")

    def _call_anthropic(self, prompt: str) -> str:

        try:
            import anthropic
        except ImportError:
            raise ImportError("anthropic package required. Install with: pip install anthropic")

        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError("ANTHROPIC_API_KEY environment variable not set")

        client = anthropic.Anthropic(api_key=api_key)

        message = client.messages.create(
            model=self.model,
            max_tokens=2048,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )

        return message.content[0].text

    def _call_openai(self, prompt: str) -> str:

        try:
            import openai
        except ImportError:
            raise ImportError("openai package required. Install with: pip install openai")

        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OPENAI_API_KEY environment variable not set")

        client = openai.OpenAI(api_key=api_key)

        response = client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "user", "content": prompt}
            ],
            max_tokens=2048
        )

        return response.choices[0].message.content


class GlobalMemoryGenerator:


    DEFAULT_OUTPUT_PATH = "memory/global_memory_prompt.txt"
    DEFAULT_STATE_PATH = "memory/global_memory_state.json"

    def __init__(
        self,
        ablation_dir: Path,
        api_provider: str = "anthropic",
        model: str = "claude-sonnet-4-20250514",
        output_path: Optional[Path] = None,
        state_path: Optional[Path] = None
    ):

        self.ablation_dir = Path(ablation_dir)
        self.collector = AblationResultsCollector(self.ablation_dir)
        self.extractor = InsightExtractor(api_provider, model)
        self.output_path = output_path or Path(self.DEFAULT_OUTPUT_PATH)
        self.state_path = state_path or Path(self.DEFAULT_STATE_PATH)

    def _load_state(self) -> Optional[ProcessedState]:

        if not self.state_path.exists():
            return None

        try:
            with open(self.state_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            return ProcessedState(
                processed_samples=data.get('processed_samples', {}),
                last_update=data.get('last_update', ''),
                version=data.get('version', 1)
            )
        except Exception as e:
            logger.warning(f"Failed to load state: {e}")
            return None

    def _save_state(self, state: ProcessedState) -> None:

        self.state_path.parent.mkdir(parents=True, exist_ok=True)

        data = {
            'processed_samples': state.processed_samples,
            'last_update': state.last_update,
            'version': state.version
        }
        with open(self.state_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)

    def generate(self, incremental: bool = False) -> Tuple[str, int]:

        logger.info(f"Collecting results from {self.ablation_dir}")

        if incremental:
            existing_state = self._load_state()
            existing_memory = self.load_global_memory(self.output_path)

            if existing_state and existing_memory:
                summary, new_state = self.collector.collect_all_results(
                    processed_state=existing_state,
                    only_new=True
                )

                new_samples = summary.total_samples
                logger.info(f"Found {new_samples} new samples to analyze")

                if new_samples == 0:
                    logger.info("No new samples, keeping existing memory")
                    return existing_memory, 0

                logger.info(
                    f"New data: {len(summary.hit_no_sig_cases)} hit_no_sig, "
                    f"{len(summary.success_cases)} success, "
                    f"{len(summary.recovery_patterns)} recovery patterns"
                )

                logger.info("Updating insights with new data...")
                global_memory = self.extractor.update_insights(existing_memory, summary)

                self._save_state(new_state)

                return global_memory, new_samples
            else:
                logger.info("No existing memory/state found, doing full generation")

        summary, state = self.collector.collect_all_results()

        logger.info(
            f"Collected {summary.total_samples} samples, "
            f"{summary.total_iterations} iterations, "
            f"{summary.successful_samples} successful"
        )
        logger.info(
            f"Categories: {len(summary.hit_no_sig_cases)} hit_no_sig, "
            f"{len(summary.crash_cases)} crash, "
            f"{len(summary.success_cases)} success, "
            f"{len(summary.recovery_patterns)} recovery patterns"
        )

        logger.info("Extracting insights using strong LLM...")
        global_memory = self.extractor.extract_insights(summary)

        self._save_state(state)

        return global_memory, summary.total_samples

    def generate_and_save(self, incremental: bool = False) -> Tuple[Path, int]:

        global_memory, samples_count = self.generate(incremental=incremental)

        self.output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(self.output_path, 'w', encoding='utf-8') as f:
            f.write(global_memory)

        logger.info(f"Global memory saved to {self.output_path}")
        return self.output_path, samples_count

    @staticmethod
    def load_global_memory(path: Optional[Path] = None) -> Optional[str]:

        path = path or Path(GlobalMemoryGenerator.DEFAULT_OUTPUT_PATH)

        if not path.exists():
            logger.debug(f"No global memory file found at {path}")
            return None

        with open(path, 'r', encoding='utf-8') as f:
            return f.read()


def get_collection_stats(ablation_dir: Path) -> Dict[str, Any]:

    collector = AblationResultsCollector(ablation_dir)
    summary, _ = collector.collect_all_results()

    return {
        "total_samples": summary.total_samples,
        "total_iterations": summary.total_iterations,
        "successful_samples": summary.successful_samples,
        "hit_no_sig_count": len(summary.hit_no_sig_cases),
        "crash_count": len(summary.crash_cases),
        "success_count": len(summary.success_cases),
        "no_hit_count": len(summary.no_hit_cases),
        "recovery_patterns_count": len(summary.recovery_patterns),
        "models_found": list(set(
            o.model_name for o in
            summary.hit_no_sig_cases + summary.crash_cases +
            summary.success_cases + summary.no_hit_cases
        ))
    }
