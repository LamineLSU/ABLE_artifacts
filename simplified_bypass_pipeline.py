
import os
import sys
import json
import time
import re
import argparse
import threading
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, asdict, field
from typing import Dict, List, Optional, Tuple
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.append(str(Path(__file__).parent))
sys.path.append(str(Path(__file__).parent / "core"))
sys.path.append(str(Path(__file__).parent / "agents"))
sys.path.append(str(Path(__file__).parent / "prompt_strategies"))

from core.trace_loader import TraceLoader
from core.prompt_evaluator import PromptEvaluator, BatchEvaluator, EvaluationResult, YaraResult
from core.cape_vm_controller import CapeVMController
from core.yara_validator import YaraBypassValidator, sanitize_yara_rule
from core.evaluation_logger import EvaluationLogger, get_evaluation_logger
from core.global_memory import GlobalMemoryGenerator
from agents.automated_llm_agents import AutomatedAgentFactory, setup_environment_keys

from prompt_strategies import (
    get_prompt,
    list_prompts,
    get_prompt_metadata,
    format_prompt,
    RECOMMENDED_PROMPT,
    ALL_PROMPTS
)
from prompt_strategies.prompt_loader import PromptLoader


DEFAULT_VM_CONFIGS = [
    {'name': 'cape_vm1', 'host': '192.168.52.144', 'user': 'cape', 'password': '12345', 'active': True},
    {'name': 'cape_vm2', 'host': '192.168.52.145', 'user': 'cape', 'password': '12345', 'active': True},
    {'name': 'cape_vm3', 'host': '192.168.52.147', 'user': 'cape', 'password': '12345', 'active': True},
]


class BypassStatus(Enum):

    PENDING = "pending"
    RULE_HIT = "rule_hit"
    BYPASS_SUCCESS = "bypass_success"
    BYPASS_CRASHED = "bypass_crashed"
    BYPASS_FAILED = "bypass_failed"
    ERROR = "error"


IGNORED_SIGNATURES = {
    'exec_crash',
    'crash',
    'exception',
    'access_violation',
    'stack_overflow',
    'heap_corruption',
    'invalid_instruction',
    'segfault',
}


@dataclass
class BypassAttempt:

    iteration: int
    prompt_version: str
    yara_rule: str
    pattern_type: str
    confidence: int
    opcodes: str

    task_id: Optional[str] = None
    status: BypassStatus = BypassStatus.PENDING
    rule_hit: bool = False

    baseline_signatures: int = 0
    new_signatures: int = 0
    new_signature_names: List[str] = field(default_factory=list)
    new_signature_details: List[Dict] = field(default_factory=list)

    failure_reason: Optional[str] = None
    improvement_suggestions: List[str] = field(default_factory=list)
    debugger_log: Optional[str] = None

    raw_response: str = ""
    yara_file: Optional[str] = None


@dataclass
class EvolutionState:

    sha256: str
    prompt_version: str
    iterations: List[BypassAttempt] = field(default_factory=list)
    best_attempt: Optional[BypassAttempt] = None
    best_score: int = 0

    optimization_history: List[str] = field(default_factory=list)
    successful_patterns: List[str] = field(default_factory=list)
    failed_patterns: List[str] = field(default_factory=list)


@dataclass
class PE2HistoryEntry:

    step: int
    accuracy: float
    original_prompt: str
    evolved_prompt: str
    limitations: str
    changes: str
    result: str
    gradient: str


@dataclass
class PE2State:

    prompt_version: str
    current_prompt: str
    history: List[PE2HistoryEntry] = field(default_factory=list)

    total_samples: int = 0
    successful_samples: int = 0

    last_change_direction: str = ""
    consecutive_improvements: int = 0
    consecutive_degradations: int = 0

    def get_accuracy(self) -> float:

        if self.total_samples == 0:
            return 0.0
        return (self.successful_samples / self.total_samples) * 100

    def build_history_string(self) -> str:

        if not self.history:
            return PE2_HISTORY_EMPTY

        entries = []
        for entry in self.history[-5:]:
            entry_str = PE2_HISTORY_ENTRY_TEMPLATE.format(
                step=entry.step,
                accuracy=f"{entry.accuracy:.1f}",
                limitations=entry.limitations,
                changes=entry.changes,
                result=entry.result
            )
            entries.append(entry_str)

        return PE2_HISTORY_TEMPLATE.format(history_entries="\n".join(entries))

    def add_entry(self, gradient: str, limitations: str, changes: str,
                  new_prompt: str, new_accuracy: float):

        old_accuracy = self.get_accuracy()

        if new_accuracy > old_accuracy + 5:
            result = "improved"
            self.consecutive_improvements += 1
            self.consecutive_degradations = 0
        elif new_accuracy < old_accuracy - 5:
            result = "degraded"
            self.consecutive_degradations += 1
            self.consecutive_improvements = 0
        else:
            result = "no change"

        entry = PE2HistoryEntry(
            step=len(self.history) + 1,
            accuracy=new_accuracy,
            original_prompt=self.current_prompt,
            evolved_prompt=new_prompt,
            limitations=limitations,
            changes=changes,
            result=result,
            gradient=gradient
        )

        self.history.append(entry)
        self.current_prompt = new_prompt


FEEDBACK_ANALYSIS_PROMPT = """
You are analyzing the results of a YARA bypass rule execution.

{original_trace}

```yara
{yara_rule}
```

- **Rule Hit**: {rule_hit}
- **Baseline Signatures**: {baseline_sigs}
- **New Signatures After Bypass**: {new_sigs}
- **New Signature Names**: {new_sig_names}
- **Crash Occurred**: {crashed}
- **Crash Signatures**: {crash_sigs}
{debugger_section}

Analyze why the bypass {status}:

{crash_analysis}

1. **Pattern Analysis**:
   - Did the YARA pattern match the correct instruction sequence?
   - Was the pattern too specific (won't match variants)?
   - Was the pattern too generic (matches wrong locations)?
   - Did the skip offset cause execution to jump to invalid code?
   - If debugger log is available, analyze exactly where execution went wrong

2. **Improvement Suggestions**:
   - What should be changed to avoid crashes and find more signatures?
   - Should we target a different instruction?
   - Should we use different wildcards or skip offset?
   - If the debugger shows a specific crash address, how can we avoid it?


**STATUS_ANALYSIS**: [Why did this {status}?]

**ROOT_CAUSE**: [The fundamental reason for success/failure/crash]

**SUGGESTED_FIX**: [Specific actionable fix]

**NEW_OPCODES_GENERIC**: [Improved hex pattern with wildcards, or "KEEP_CURRENT"]

**NEW_SKIP_OFFSET**: [New skip offset if crash occurred, or "KEEP_CURRENT"]

**REASONING**: [1-2 sentences explaining the suggested changes]
"""


RULE_EVOLUTION_PROMPT = """
You are evolving a YARA bypass rule based on execution feedback.

We are trying to bypass malware evasion for sample: {sha256}

{evolution_history}

```yara
{best_rule}
```

{latest_analysis}

{original_trace}


Based on the feedback, generate an IMPROVED YARA bypass rule.

**Key Principles:**
1. Learn from failures - don't repeat the same mistakes
2. Use momentum - if a direction is working, continue it
3. Be specific enough to hit the target, generic enough for variants

===============================================================================
BYPASS STRATEGY EVOLUTION
===============================================================================

Consider THREE bypass strategies when evolving:

**STRATEGY A: EVASION CHECK (60% success - try first)**
- Location: FIRST 30% of trace
- Pattern: CALL → TEST EAX → JE/JNE
- Target the check function, not the exit

**STRATEGY B: EXIT DECISION (25% success - try if A fails)**
- Location: BEFORE the exit call
- Pattern: Conditional check before ExitProcess/TerminateProcess
- Sometimes the exit itself has conditional logic

**STRATEGY C: EVASION TECHNIQUE (15% success - for specific cases)**
- RDTSC timing, CPUID VM detect, Sleep acceleration
- Look for unique instruction sequences

**If previous attempts show "Rule hit but no new signatures":**
- Your pattern matched but the WRONG location
- Move EARLIER in the trace (Strategy A)
- Or check if there's conditional logic before exit (Strategy B)
- The bypass point must be where the DECISION is made, not the action

===============================================================================
PATTERN EXAMPLES
===============================================================================

Select 3 DIFFERENT patterns from the trace. Examples of valid patterns:
- {{ 85 C0 0F 84 ?? ?? ?? ?? 8B 45 FC }}  -- test+je+mov (specific stack offset)
- {{ 83 F8 01 74 12 8B 4D F8 }}  -- cmp+je+mov (concrete bytes, very specific)
- {{ 3D 00 10 00 00 0F 82 }}  -- cmp eax,imm32 + jb (concrete comparison value)

Target exit-related instructions as bypass points - the instruction that triggers program termination is often an effective 6-byte pattern.

**CRITICAL: All patterns MUST come from the original trace above!**
- Every hex byte in your pattern must exist in the TRACE DATA
- Do NOT invent or guess byte sequences - copy them from the trace
- Patterns not found in the trace will match wrong locations and cause crashes

**PATTERN SPECIFICITY:**
- Use CONCRETE bytes from the trace (copy exact hex values, not wildcards) for most patterns
- Only use wildcards (??) for bytes that MUST vary (like CALL/JMP offsets)
- More specific patterns = less chance of matching wrong locations = fewer crashes

Each pattern must be 6-20 bytes. Use ?? for addresses/offsets.


**EVOLUTION_REASONING**: [What changes are you making and why?]

**PATTERN_TYPE**: [CALL_TEST_JE | API_CHECK | CMP_SETZ | VM_DETECT | DEBUG_CHECK | TIMING_CHECK | OTHER]

**CONFIDENCE**: [0-100]

**REASONING**: [Why these evolved patterns should work better]

**YARA_RULE**:
```yara
rule Bypass_Sample_Evolved
{{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = {{ [6-20 bytes with wildcards] }}
        $pattern1 = {{ [6-20 bytes - DIFFERENT sequence] }}
        $pattern2 = {{ [6-20 bytes - DIFFERENT sequence] }}

    condition:
        any of them
}}
```


1. **EXACTLY 3 PATTERNS**: You MUST have `$pattern0`, `$pattern1`, `$pattern2` - no more, no less
2. **CAPE_OPTIONS REQUIRED**: You MUST include cape_options referencing all 3 patterns
3. **6-20 BYTES PER PATTERN**: Each pattern must be 6-20 bytes
4. **ALL 3 PATTERNS MUST BE DIFFERENT**: Do not duplicate patterns
5. Use wildcards (??) for all address/offset bytes
"""


PE2_INSPECTOR = """
You are analyzing why a prompt for YARA bypass rule generation failed.

```
{current_prompt}
```

The prompt is concatenated with a malware execution trace. The model reads the prompt, then analyzes the trace, and outputs a YARA rule with bypass pattern.

```
[PROMPT]
{{trace}}
[Expected Output: YARA rule identifying evasion bypass point]
```

The prompt produced incorrect YARA rules for these examples. The ground-truth labels (correct bypass points) are absolutely correct.

{failure_examples}

For EACH failed example, analyze using this template:

**Input (Trace Summary)**: {trace_summary}
**Generated Output**: {generated_output}
**Ground-Truth Label**: {ground_truth}
**Is the output correct?**: [Yes/No] - [reasoning]
**Did the model follow the prompt?**: [Yes/No] - [reasoning]
**Does the prompt describe the task correctly?**: [Yes/No] - [reasoning]
**Is editing the prompt necessary?**: [Yes/No] - [reasoning]
**Specific suggestions to fix**: [detailed, actionable suggestions]

After analyzing all examples, provide:

**GRADIENT** (summary of what's wrong with the prompt):
[2-3 specific reasons why the prompt is failing, based on the examples above]
"""

PE2_PROPOSER = """
You are a Prompt Engineering Expert collaborating to refine a prompt for YARA bypass rule generation.

{instruction_context}

The following analysis identifies why the current prompt failed:

{inspector_analysis}

```
{current_prompt}
```

This shows how the prompt connects to the input trace:
```
[PROMPT CONTENT]
{{{{trace}}}}
---
[MODEL GENERATES OUTPUT HERE]
```

{pe2_history}


Based on the inspector analysis and history, improve the prompt.

**Constraints:**
- Maximum prompt length: {max_tokens} words
- You may change up to {step_size} words from the original
- Keep the Required Output Format section intact (PATTERN_TYPE, LOCATION, etc.)
- The improved prompt must still produce valid YARA rules

**Guidelines from gradient descent analogy:**
- If previous changes improved accuracy, continue in that direction (momentum)
- If previous changes hurt accuracy, try a different approach
- Small, targeted changes often work better than large rewrites

Reply with ONLY the improved prompt. Do not include explanations or other text.
"""

PE2_HISTORY_EMPTY = """
No previous evolution history. This is the first prompt optimization step.
"""

PE2_HISTORY_TEMPLATE = """
Note: Higher accuracy = better. If edits improved results, continue that direction.

{history_entries}
"""

PE2_HISTORY_ENTRY_TEMPLATE = """
* At step {step}, accuracy was {accuracy}%.
  - Limitations: {limitations}
  - Changes made: {changes}
  - Result: {result}
"""

PE2_INSTRUCTION_CONTEXT = """
Prompt engineering is developing and optimizing prompts to efficiently use language models.

Key concepts:
1. **Instruction**: Specific task you want the model to perform
2. **Context**: External information that steers the model to better responses
3. **Input Data**: The input to find a response for
4. **Output Indicator**: The type or format of expected output

Tips for effective prompts:
- Be specific and detailed about the desired outcome
- Provide examples to demonstrate correct behavior
- Say what TO DO, not what NOT to do
- Use clear separators between sections (
- Place instructions at the beginning of the prompt
"""

PE2_PROMPT_PROPOSER_SIMPLE = """
You are a Prompt Engineering Expert. Your task is to improve a prompt for YARA bypass rule generation.

```
{current_prompt}
```

{gradient}

{pe2_history}

Based on the failure analysis and history, generate an improved prompt.
- Keep the same output format (PATTERN_TYPE, LOCATION, OPCODES, etc.)
- Add specific guidance to address the failures
- Maximum length: {max_tokens} words

Reply with ONLY the improved prompt.
"""


class MultiVMManager:


    def __init__(self, vm_configs: List[Dict]):
        self.vms = []
        self.vm_controllers = {}
        self.vm_locks = {}
        self.vm_tasks = {}

        for config in vm_configs:
            if config.get('active', True):
                vm_info = {
                    'name': config.get('name', f"vm_{len(self.vms)}"),
                    'host': config.get('host', '192.168.52.144'),
                    'user': config.get('user', 'cape'),
                    'password': config.get('password', '12345'),
                    'active': True,
                    'connected': False,
                    'busy': False
                }
                self.vms.append(vm_info)
                self.vm_locks[vm_info['name']] = threading.Lock()
                self.vm_tasks[vm_info['name']] = None

    def get_active_vms(self) -> List[Dict]:

        return [vm for vm in self.vms if vm['active']]

    def connect_all(self) -> int:

        connected = 0
        for vm in self.vms:
            try:
                controller = CapeVMController(
                    host=vm['host'],
                    user=vm['user'],
                    password=vm['password'],
                    vm_name=vm['name']
                )
                if controller.connect():
                    self.vm_controllers[vm['name']] = controller
                    vm['connected'] = True
                    connected += 1
                    print(f"    [+] Connected to {vm['name']} ({vm['host']})")
                else:
                    print(f"    [!] Failed to connect to {vm['name']} ({vm['host']})")
            except Exception as e:
                print(f"    [!] Error connecting to {vm['name']}: {e}")
        return connected

    def close_all(self):

        for name, controller in self.vm_controllers.items():
            try:
                controller.close()
            except:
                pass
        self.vm_controllers = {}

    def get_free_vm(self) -> Optional[Tuple[str, 'CapeVMController']]:

        for vm in self.vms:
            if vm['connected'] and not vm['busy']:
                name = vm['name']
                with self.vm_locks[name]:
                    if not vm['busy']:
                        vm['busy'] = True
                        return (name, self.vm_controllers[name])
        return None

    def release_vm(self, vm_name: str):

        for vm in self.vms:
            if vm['name'] == vm_name:
                with self.vm_locks[vm_name]:
                    vm['busy'] = False
                    self.vm_tasks[vm_name] = None
                break

    def check_vm_has_pending_tasks(self, vm_name: str) -> bool:

        if vm_name not in self.vm_controllers:
            return False

        controller = self.vm_controllers[vm_name]
        try:
            output, _, ret = controller.ssh_client.execute_command(
                "curl -s http://localhost:8000/cuckoo/status 2>/dev/null || echo '{}'",
                check_return_code=False
            )
            if output:
                try:
                    status = json.loads(output)
                    tasks = status.get('tasks', {})
                    pending = tasks.get('pending', 0)
                    running = tasks.get('running', 0)
                    return (pending + running) > 0
                except:
                    pass
        except:
            pass
        return False

    def wait_for_free_vm(self, timeout: int = 600) -> Optional[Tuple[str, 'CapeVMController']]:

        start_time = time.time()
        while time.time() - start_time < timeout:
            result = self.get_free_vm()
            if result:
                return result
            time.sleep(10)
        return None


class SimplifiedBypassPipeline:


    def __init__(self,
                 binary_path: Optional[str] = None,
                 llm_type: str = "auto",
                 agent_config: Optional[Dict] = None,
                 vm_configs: Optional[List[Dict]] = None,
                 trace_dir: Optional[str] = None,
                 output_dir: Optional[str] = None,
                 multi_vm: bool = False,
                 evolving: bool = False,
                 max_iterations: int = 5,
                 min_signature_improvement: int = 1,
                 early_stop: bool = True,
                 pe2_enabled: bool = False,
                 retry_on_error: bool = True,
                 max_retries: int = 3,
                 use_retry_feedback: bool = True,
                 parallel_baseline: bool = False,
                 continue_from: Optional[str] = None,
                 start_iteration: int = 0):

        if binary_path:
            if binary_path.startswith('/'):
                self.binary_path = binary_path
                self.is_linux_binary_path = True
            else:
                self.binary_path = Path(binary_path)
                self.is_linux_binary_path = False
        else:
            self.binary_path = None
            self.is_linux_binary_path = False

        self.llm_type = llm_type
        self.multi_vm_enabled = multi_vm
        self.evolving_enabled = evolving
        self.max_iterations = max_iterations
        self.min_signature_improvement = min_signature_improvement
        self.early_stop = early_stop
        self.pe2_enabled = pe2_enabled
        self.parallel_baseline = parallel_baseline
        self.retry_on_error = retry_on_error
        self.max_retries = max_retries
        self.use_retry_feedback = use_retry_feedback
        self.continue_from = continue_from
        self.start_iteration = start_iteration
        self.continuation_state = None

        if continue_from:
            self.continuation_state = self._load_continuation_state(continue_from)
            if self.continuation_state:
                if self.continuation_state.get('success', False):
                    print(f"[!] WARNING: The case in {continue_from} already succeeded!")
                    print(f"[!] Skipping continuation - no need to continue successful cases.")
                    self.continuation_state = None
                else:
                    print(f"[Continue] Loaded previous state from: {continue_from}")
                    print(f"[Continue] Previous iterations: {self.continuation_state.get('completed_iterations', 0)}")
                    print(f"[Continue] Starting from iteration: {start_iteration}")

        if vm_configs:
            self.vm_configs = vm_configs
        else:
            if multi_vm:
                self.vm_configs = DEFAULT_VM_CONFIGS
            else:
                self.vm_configs = [DEFAULT_VM_CONFIGS[0]]

        self.vm_manager = None

        if output_dir:
            self.output_dir = Path(output_dir)
        else:
            self.output_dir = Path(__file__).parent / "bypass_output" / datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.trace_loader = TraceLoader(trace_dir)

        self.prompt_loader = PromptLoader()

        self._setup_llm(agent_config)

        self.evaluator = PromptEvaluator(self.smart_orchestrator, str(self.output_dir))

        eval_log_dir = self.output_dir / "evaluation_logs"
        self.eval_logger = EvaluationLogger(str(eval_log_dir))

        self.pe2_states: Dict[str, PE2State] = {}

        self.global_memory = GlobalMemoryGenerator.load_global_memory()
        if self.global_memory:
            print(f"[GlobalMemory] Loaded global memory prompt ({len(self.global_memory)} chars)")

        self.results = {
            'pipeline': 'Simplified Bypass Pipeline with CAPE Validation',
            'timestamp': datetime.now().isoformat(),
            'llm_type': self.llm_type,
            'binary_path': str(self.binary_path) if self.binary_path else None,
            'multi_vm_enabled': self.multi_vm_enabled,
            'evolving_enabled': self.evolving_enabled,
            'max_iterations': self.max_iterations,
            'min_signature_improvement': self.min_signature_improvement,
            'pe2_enabled': self.pe2_enabled,
            'retry_on_error': self.retry_on_error,
            'max_retries': self.max_retries,
            'use_retry_feedback': self.use_retry_feedback,
            'vm_configs': [{'name': vm.get('name'), 'host': vm.get('host')} for vm in self.vm_configs],
            'samples_processed': [],
            'evaluations': {},
            'yara_rules_generated': [],
            'baseline_result': None,
            'cape_validations': [],
            'successful_bypasses': [],
            'comparison': {},
            'evolution_states': {},
            'pe2_evolution': {},
            'retry_summaries': {}
        }

    def _binary_exists(self) -> bool:

        if not self.binary_path:
            return False
        if self.is_linux_binary_path:
            return True
        else:
            return self.binary_path.exists()

    def _get_binary_name(self) -> str:

        if not self.binary_path:
            return "unknown"
        if self.is_linux_binary_path:
            return self.binary_path.split('/')[-1]
        else:
            return self.binary_path.name

    def _load_continuation_state(self, strategy_file_path: str) -> Optional[Dict]:

        try:
            strategy_path = Path(strategy_file_path)
            if not strategy_path.exists():
                print(f"[!] Continuation file not found: {strategy_file_path}")
                return None

            with open(strategy_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            iterations = data.get('iterations', [])

            evolution_history = []
            successful_patterns = []
            failed_patterns = []

            for iter_data in iterations:
                iter_num = iter_data.get('iteration_number', 0)
                new_sigs = iter_data.get('new_signatures', 0)
                feedback = iter_data.get('feedback_given', '')

                llm_query = iter_data.get('llm_query', {})
                pattern_type = llm_query.get('pattern_type', 'UNKNOWN')

                history_entry = f"Iteration {iter_num + 1}: {feedback}"
                evolution_history.append(history_entry)

                if new_sigs > 0:
                    successful_patterns.append(pattern_type)
                else:
                    failed_patterns.append(pattern_type)

            state = {
                'success': data.get('success', False),
                'prompt_version': data.get('prompt_version', 'v0'),
                'prompt_name': data.get('prompt_name', ''),
                'completed_iterations': len(iterations),
                'total_iterations_before': data.get('total_iterations', 0),
                'best_score': data.get('best_score', 0),
                'best_iteration': data.get('best_iteration'),
                'iterations': iterations,
                'evolution_history': evolution_history,
                'successful_patterns': successful_patterns,
                'failed_patterns': failed_patterns,
            }

            if iterations:
                last_iter = iterations[-1]
                state['last_iteration'] = {
                    'iteration_number': last_iter.get('iteration_number', 0),
                    'llm_query': last_iter.get('llm_query', {}),
                    'cape_analysis': last_iter.get('cape_analysis', {}),
                    'feedback_given': last_iter.get('feedback_given', ''),
                    'success': last_iter.get('success', False),
                    'new_signatures': last_iter.get('new_signatures', 0),
                }
            else:
                state['last_iteration'] = None

            return state

        except (json.JSONDecodeError, KeyError, IOError) as e:
            print(f"[!] Error loading continuation state: {e}")
            return None

    def _setup_llm(self, agent_config: Optional[Dict] = None):

        api_keys = setup_environment_keys()

        if self.llm_type == "auto":
            preferred_providers = ["openai", "anthropic", "ollama", "manual"]
        elif self.llm_type == "api_only":
            preferred_providers = ["openai", "anthropic", "manual"]
        elif self.llm_type == "local_only":
            preferred_providers = ["ollama", "manual"]
        else:
            preferred_providers = [self.llm_type, "manual"]

        models = {}
        if agent_config:
            models['openai'] = agent_config.get('openai_model', 'gpt-4')
            models['anthropic'] = agent_config.get('anthropic_model', 'claude-3-5-sonnet-20241022')
            models['ollama'] = agent_config.get('ollama_model', 'qwen3:latest')

        self.smart_orchestrator = AutomatedAgentFactory.create_smart_orchestrator(
            preferred_providers, api_keys, models
        )

        provider_info = self.smart_orchestrator.get_provider_info()
        print(f"[+] LLM Provider: {provider_info['current_provider']}")
        print(f"[+] Model: {provider_info['model']}")

        available = [p['name'] for p in provider_info['available_providers'] if p['available']]
        print(f"[+] Available LLM options: {', '.join(available)}")


    def _get_or_create_pe2_state(self, prompt_version: str) -> PE2State:

        if prompt_version not in self.pe2_states:
            original_prompt = get_prompt(prompt_version)
            self.pe2_states[prompt_version] = PE2State(
                prompt_version=prompt_version,
                current_prompt=original_prompt
            )
        return self.pe2_states[prompt_version]

    def _pe2_run_inspector(self, prompt_version: str, failure_examples: List[Dict]) -> str:

        if not failure_examples:
            return "No failures to analyze."

        pe2_state = self._get_or_create_pe2_state(prompt_version)

        examples_text = ""
        for i, ex in enumerate(failure_examples[:3], 1):
            examples_text += f"""
**Trace Summary**: {ex.get('trace_summary', 'N/A')[:500]}
**Generated YARA Rule**:
```
{ex.get('generated_rule', 'N/A')[:500]}
```
**Expected Pattern Location**: {ex.get('expected_location', 'N/A')}
**Failure Reason**: {ex.get('failure_reason', 'Unknown')}
"""

        inspector_prompt = PE2_INSPECTOR.format(
            current_prompt=pe2_state.current_prompt[:2000],
            failure_examples=examples_text,
            example_id="{id}",
            trace_summary="{trace}",
            generated_output="{output}",
            ground_truth="{label}"
        )

        print(f"    [PE2] Running Inspector analysis...")
        response = self.smart_orchestrator.chat(inspector_prompt)

        gradient = response
        if "**GRADIENT**" in response:
            gradient = response.split("**GRADIENT**")[-1].strip()

        return gradient

    def _pe2_run_proposer(self, prompt_version: str, gradient: str) -> Tuple[str, str, str]:

        pe2_state = self._get_or_create_pe2_state(prompt_version)

        proposer_prompt = PE2_PROPOSER.format(
            instruction_context=PE2_INSTRUCTION_CONTEXT,
            inspector_analysis=gradient,
            current_prompt=pe2_state.current_prompt,
            pe2_history=pe2_state.build_history_string(),
            max_tokens=800,
            step_size=100
        )

        print(f"    [PE2] Running Proposer to evolve prompt...")
        new_prompt = self.smart_orchestrator.chat(proposer_prompt)

        if "```" in new_prompt:
            parts = new_prompt.split("```")
            for part in parts:
                if "TRACE" in part or "PATTERN_TYPE" in part:
                    new_prompt = part.strip()
                    break

        limitations = gradient[:200] if gradient else "Unknown"
        changes = f"Evolved prompt based on {len(pe2_state.history)} previous iterations"

        return new_prompt, limitations, changes

    def _pe2_evolve_prompt(self, prompt_version: str,
                           failure_examples: List[Dict],
                           new_accuracy: float) -> str:

        if not self.pe2_enabled:
            return get_prompt(prompt_version)

        pe2_state = self._get_or_create_pe2_state(prompt_version)

        print(f"\n    [PE2] ============================================")
        print(f"    [PE2] Evolving prompt: {prompt_version}")
        print(f"    [PE2] Current accuracy: {pe2_state.get_accuracy():.1f}%")
        print(f"    [PE2] History entries: {len(pe2_state.history)}")
        print(f"    [PE2] ============================================")

        gradient = self._pe2_run_inspector(prompt_version, failure_examples)
        print(f"    [PE2] Gradient: {gradient[:200]}...")

        new_prompt, limitations, changes = self._pe2_run_proposer(prompt_version, gradient)

        pe2_state.add_entry(
            gradient=gradient,
            limitations=limitations,
            changes=changes,
            new_prompt=new_prompt,
            new_accuracy=new_accuracy
        )

        pe2_state.total_samples += 1
        if new_accuracy > 0:
            pe2_state.successful_samples += 1

        print(f"    [PE2] Prompt evolved. New history length: {len(pe2_state.history)}")
        print(f"    [PE2] Momentum: {pe2_state.consecutive_improvements} consecutive improvements")

        self.results['pe2_evolution'][prompt_version] = {
            'history_length': len(pe2_state.history),
            'current_accuracy': pe2_state.get_accuracy(),
            'total_samples': pe2_state.total_samples,
            'last_gradient': gradient[:500],
            'last_changes': changes
        }

        return new_prompt

    def _pe2_get_current_prompt(self, prompt_version: str) -> str:

        if not self.pe2_enabled:
            return get_prompt(prompt_version)

        if prompt_version in self.pe2_states:
            return self.pe2_states[prompt_version].current_prompt
        return get_prompt(prompt_version)

    def list_available_samples(self) -> List[str]:

        samples = self.trace_loader.list_samples()
        print(f"[+] Found {len(samples)} samples with traces")
        for s in samples[:5]:
            info = self.trace_loader.get_sample_info(s)
            if info:
                print(f"    - {s[:16]}... ({info['total_traces']} traces)")
        if len(samples) > 5:
            print(f"    ... and {len(samples) - 5} more")
        return samples

    def generate_yara_rules(self,
                            sha256: str,
                            prompt_versions: Optional[List[str]] = None) -> List[Tuple[str, YaraResult]]:

        print(f"\n{'='*60}")
        print(f"PHASE 1: GENERATING YARA RULES")
        print(f"Sample: {sha256[:16]}...")
        print(f"{'='*60}")

        if not self.trace_loader.sample_exists(sha256):
            print(f"[!] Sample not found: {sha256}")
            return []

        trace = self.trace_loader.get_all_traces_for_prompt(sha256)
        if not trace:
            print(f"[!] Could not load trace for: {sha256}")
            return []

        print(f"[+] Loaded ALL traces ({len(trace)} chars)")

        if prompt_versions:
            versions = prompt_versions
        else:
            versions = list(ALL_PROMPTS.keys())

        print(f"[+] Using prompt versions: {', '.join(v.upper() for v in versions)}")
        if self.retry_on_error:
            print(f"[+] Pre-VM retry enabled: max_retries={self.max_retries}, feedback={self.use_retry_feedback}")

        generated_rules = []

        for version in versions:
            print(f"\n[*] Generating with {version.upper()}...")

            if self.retry_on_error:
                result, retry_summary = self.evaluator.evaluate_single_prompt_with_retry(
                    trace=trace,
                    prompt_version=version,
                    max_retries=self.max_retries,
                    use_feedback=self.use_retry_feedback
                )
                self.results['retry_summaries'][f"{sha256[:16]}_{version}"] = retry_summary
            else:
                result = self.evaluator.evaluate_single_prompt(trace, version)

            if result.parse_success and result.yara_rule:
                yara_file = self.output_dir / f"{sha256[:16]}_{version}_bypass.yar"
                with open(yara_file, 'w', encoding='utf-8') as f:
                    f.write(f"// Generated by Simplified Bypass Pipeline\n")
                    f.write(f"// Sample: {sha256}\n")
                    f.write(f"// Prompt: {version.upper()}\n")
                    f.write(f"// Pattern Type: {result.pattern_type}\n")
                    f.write(f"// Confidence: {result.confidence}%\n")
                    if self.retry_on_error:
                        retry_attempts = len(self.results['retry_summaries'].get(f"{sha256[:16]}_{version}", []))
                        f.write(f"// Retry Attempts: {retry_attempts}\n")
                    f.write(f"\n")
                    f.write(result.yara_rule)

                generated_rules.append((str(yara_file), result))
                self.results['yara_rules_generated'].append(str(yara_file))
                print(f"    [+] Generated: {yara_file.name}")
                print(f"    [+] Pattern: {result.pattern_type}, Confidence: {result.confidence}%")
            else:
                print(f"    [!] Failed to generate valid rule")
                if result.error_message:
                    print(f"    [!] Error: {result.error_message}")

        print(f"\n[+] Generated {len(generated_rules)} YARA rules")
        return generated_rules

    def validate_in_cape(self, yara_rules: List[Tuple[str, YaraResult]]) -> Dict:

        print(f"\n{'='*60}")
        print(f"PHASE 2: CAPE VALIDATION")
        print(f"{'='*60}")

        if not self.binary_path:
            print("[!] No binary path specified - skipping CAPE validation")
            print("[!] Use --binary to specify the malware sample for validation")
            return {'validations': [], 'success_rate': 0, 'skipped': True}

        if not self._binary_exists():
            print(f"[!] Binary not found: {self.binary_path}")
            return {'validations': [], 'success_rate': 0, 'error': 'Binary not found'}

        print(f"[+] Binary: {self._get_binary_name()}")
        print(f"[+] YARA rules to test: {len(yara_rules)}")

        print(f"\n[*] Connecting to CAPE ({self.vm_config['host']})...")
        cape = CapeVMController(
            host=self.vm_config['host'],
            user=self.vm_config['user'],
            password=self.vm_config['password']
        )

        if not cape.connect():
            print("[!] Failed to connect to CAPE")
            return {'validations': [], 'success_rate': 0, 'error': 'Connection failed'}

        if not cape.start_services():
            print("[!] Failed to start CAPE services")
            cape.close()
            return {'validations': [], 'success_rate': 0, 'error': 'Services failed'}

        print("[*] Waiting for CAPE to be ready...")
        time.sleep(30)

        validations = []

        for yara_file, yara_result in yara_rules:
            rule_name = Path(yara_file).stem
            print(f"\n[*] Testing: {rule_name}")
            print(f"    Prompt: {yara_result.prompt_version.upper()}")
            print(f"    Pattern: {yara_result.pattern_type}")

            validation = {
                'yara_file': yara_file,
                'prompt_version': yara_result.prompt_version,
                'pattern_type': yara_result.pattern_type,
                'confidence': yara_result.confidence,
                'task_id': None,
                'success': False,
                'bypass_detected': False,
                'analysis_results': {}
            }

            try:
                cape.ssh_client.execute_command(
                    "rm -f /opt/CAPEv2/analyzer/windows/data/yara/*.yar",
                    check_return_code=False
                )

                with open(yara_file, 'r', encoding='utf-8') as f:
                    yara_content = f.read()

                if not cape.deploy_yara_rule(yara_content, "test_rule.yar"):
                    validation['error'] = "Failed to deploy YARA rule"
                    validations.append(validation)
                    continue

                time.sleep(10)

                task_id = cape.submit_sample(str(self.binary_path))

                if not task_id:
                    validation['error'] = "Failed to submit sample"
                    validations.append(validation)
                    continue

                validation['task_id'] = task_id
                print(f"    [+] Submitted as task {task_id}")

                print("    [*] Waiting for analysis...")
                max_wait = 300
                elapsed = 0

                while elapsed < max_wait:
                    time.sleep(30)
                    elapsed += 30

                    try:
                        results = cape.get_results(task_id)
                        if results:
                            validation['success'] = True
                            validation['analysis_results'] = self._analyze_cape_results(results, task_id)
                            validation['bypass_detected'] = validation['analysis_results'].get('evasion_bypassed', False)
                            print(f"    [+] Analysis complete")
                            break
                    except Exception as e:
                        pass

                    if elapsed % 60 == 0:
                        print(f"        Still waiting... ({elapsed}s)")

                if not validation['success']:
                    validation['error'] = f"Analysis timeout after {max_wait}s"

            except Exception as e:
                validation['error'] = str(e)
                print(f"    [!] Error: {e}")

            validations.append(validation)

            if validation['bypass_detected']:
                print(f"    [+] ✅ BYPASS SUCCESSFUL!")
                analysis_results = validation.get('analysis_results', {})
                self.results['successful_bypasses'].append({
                    'yara_file': yara_file,
                    'prompt_version': yara_result.prompt_version,
                    'task_id': task_id,
                    'new_signatures': analysis_results.get('signature_names', []),
                    'new_signature_details': analysis_results.get('signatures', [])
                })
            elif validation['success']:
                print(f"    [-] Bypass not detected (analysis complete)")
            else:
                print(f"    [!] ❌ Validation failed")

        cape.close()

        successful = sum(1 for v in validations if v['success'])
        bypasses = sum(1 for v in validations if v['bypass_detected'])
        total = len(validations)

        print(f"\n{'='*60}")
        print(f"CAPE VALIDATION SUMMARY")
        print(f"{'='*60}")
        print(f"[+] Rules tested: {total}")
        print(f"[+] Analyses completed: {successful}/{total}")
        print(f"[+] Successful bypasses: {bypasses}/{total}")

        if bypasses > 0:
            print(f"\n[+] ✅ WORKING BYPASSES:")
            for v in validations:
                if v['bypass_detected']:
                    print(f"    - {Path(v['yara_file']).name} ({v['prompt_version'].upper()})")

        self.results['cape_validations'] = validations

        return {
            'validations': validations,
            'total': total,
            'successful_analyses': successful,
            'successful_bypasses': bypasses,
            'success_rate': (bypasses / total * 100) if total > 0 else 0
        }

    def _run_baseline_once(self, cape: CapeVMController) -> Tuple[Optional[Dict], str]:

        try:
            print("[*] Cleaning all YARA rules for baseline...")
            cape.ssh_client.execute_command(
                "rm -f /opt/CAPEv2/analyzer/windows/data/yara/*.yar",
                check_return_code=False
            )
            time.sleep(5)

            print(f"[*] Submitting {self._get_binary_name()} for baseline analysis...")
            task_id = cape.submit_sample(str(self.binary_path))

            if not task_id:
                return None, "Failed to submit sample"

            print(f"[+] Baseline task ID: {task_id}")

            print("[*] Waiting for baseline analysis...")
            max_wait = 300
            elapsed = 0

            while elapsed < max_wait:
                time.sleep(30)
                elapsed += 30

                try:
                    results = cape.get_results(task_id)
                    if results:
                        baseline_analysis = self._analyze_cape_results(results, task_id)
                        baseline_analysis['is_baseline'] = True
                        baseline_analysis['yara_rules_active'] = False
                        baseline_analysis['task_id'] = task_id

                        print(f"[+] Baseline analysis complete")
                        print(f"    Duration: {baseline_analysis['duration']}s")
                        print(f"    API calls: {baseline_analysis['api_calls']}")
                        print(f"    Malscore: {baseline_analysis['malscore']}")
                        print(f"    Signatures: {len(baseline_analysis['signature_names'])}")

                        if len(baseline_analysis['signature_names']) == 0:
                            return baseline_analysis, "Baseline returned 0 signatures"

                        return baseline_analysis, ""
                except Exception as e:
                    pass

                if elapsed % 60 == 0:
                    print(f"    Still waiting... ({elapsed}s)")

            return None, "Baseline analysis timeout"

        except Exception as e:
            return None, f"Baseline run error: {e}"

    def run_baseline(self, cape: CapeVMController, vm_config: Dict = None) -> Optional[Dict]:

        print(f"\n{'='*60}")
        print(f"BASELINE RUN (No YARA Rules)")
        print(f"{'='*60}")

        if not self.binary_path:
            print("[!] No binary path specified - skipping baseline")
            return None

        if not self._binary_exists():
            print("[!] Binary file not found - skipping baseline")
            return None

        max_retries = 3
        consecutive_failures = 0
        vm_recovery_attempted = False

        for attempt in range(max_retries):
            print(f"\n[*] Baseline attempt {attempt + 1}/{max_retries}")

            baseline_analysis, failure_reason = self._run_baseline_once(cape)

            if baseline_analysis and not failure_reason:
                self.results['baseline_result'] = baseline_analysis
                return baseline_analysis

            consecutive_failures += 1
            print(f"[!] Baseline attempt {attempt + 1} failed: {failure_reason}")

            if baseline_analysis and failure_reason == "Baseline returned 0 signatures":
                print(f"[!] Baseline returned 0 signatures - likely CAPE/VM issue")
                baseline_analysis['baseline_incomplete'] = True

            if consecutive_failures >= 2 and not vm_recovery_attempted and vm_config:
                print(f"\n[!] {consecutive_failures} consecutive baseline failures - attempting VM recovery...")
                vm_recovery_attempted = True

                if self._restart_cape_services(vm_config):
                    print(f"[+] VM recovery successful, retrying baseline...")
                    cape.close()
                    cape = CapeVMController(
                        host=vm_config['host'],
                        user=vm_config['user'],
                        password=vm_config['password']
                    )
                    if not cape.connect():
                        print(f"[!] Failed to reconnect after VM recovery")
                        continue
                    consecutive_failures = 0
                else:
                    print(f"[!] VM recovery failed")

            if attempt < max_retries - 1:
                print(f"[*] Waiting 30 seconds before retry...")
                time.sleep(30)

        print(f"[!] Baseline failed after {max_retries} attempts")

        if baseline_analysis:
            baseline_analysis['baseline_failed'] = True
            self.results['baseline_result'] = baseline_analysis
            return baseline_analysis

        self.results['baseline_result'] = {
            'baseline_failed': True,
            'signature_names': [],
            'signature_count': 0
        }
        return None

    def run_baseline_multi_vm(self) -> Optional[Dict]:

        print(f"\n{'='*60}")
        print(f"PARALLEL BASELINE RUN (All VMs)")
        print(f"{'='*60}")

        if not self.binary_path:
            print("[!] No binary path specified - skipping baseline")
            return None

        if not self._binary_exists():
            print("[!] Binary file not found - skipping baseline")
            return None

        if not self.vm_configs:
            print("[!] No VMs configured - skipping baseline")
            return None

        print(f"[+] Binary: {self._get_binary_name()}")
        print(f"[+] VMs configured: {len(self.vm_configs)}")

        print(f"\n[*] Connecting to all VMs...")
        vm_controllers = {}
        for vm_config in self.vm_configs:
            vm_name = vm_config.get('name', vm_config['host'])
            try:
                controller = CapeVMController(
                    host=vm_config['host'],
                    user=vm_config['user'],
                    password=vm_config['password']
                )
                if controller.connect():
                    vm_controllers[vm_name] = (controller, vm_config)
                    print(f"    [+] Connected to {vm_name}")
                else:
                    print(f"    [!] Failed to connect to {vm_name}")
            except Exception as e:
                print(f"    [!] Error connecting to {vm_name}: {e}")

        if not vm_controllers:
            print("[!] No VMs connected - baseline failed")
            return None

        print(f"[+] Connected to {len(vm_controllers)} VMs")

        print(f"\n[*] Checking VM availability (pending/running tasks)...")
        free_vms = {}
        busy_vms = []

        for vm_name, (controller, vm_config) in vm_controllers.items():
            try:
                output, _, ret = controller.ssh_client.execute_command(
                    "curl -s http://localhost:8000/cuckoo/status 2>/dev/null || echo '{}'",
                    check_return_code=False
                )
                pending = 0
                running = 0
                if output:
                    try:
                        status = json.loads(output)
                        tasks = status.get('tasks', {})
                        pending = tasks.get('pending', 0)
                        running = tasks.get('running', 0)
                    except:
                        pass

                if (pending + running) > 0:
                    print(f"    [!] {vm_name}: BUSY (pending={pending}, running={running}) - skipping")
                    busy_vms.append(vm_name)
                    try:
                        controller.close()
                    except:
                        pass
                else:
                    print(f"    [+] {vm_name}: FREE - will use for baseline")
                    free_vms[vm_name] = (controller, vm_config)
            except Exception as e:
                print(f"    [?] {vm_name}: Could not check status ({e}) - assuming free")
                free_vms[vm_name] = (controller, vm_config)

        if not free_vms:
            print(f"[!] No free VMs available - all {len(busy_vms)} VMs are busy")
            for vm_name, (controller, _) in vm_controllers.items():
                try:
                    controller.close()
                except:
                    pass
            return None

        print(f"[+] Using {len(free_vms)} free VMs (skipped {len(busy_vms)} busy VMs)")
        vm_controllers = free_vms

        print(f"\n[*] Starting CAPE services on all VMs...")
        for vm_name, (controller, _) in vm_controllers.items():
            try:
                if controller.start_services():
                    print(f"    [+] Services started on {vm_name}")
                else:
                    print(f"    [!] Failed to start services on {vm_name}")
            except Exception as e:
                print(f"    [!] Error starting services on {vm_name}: {e}")

        print("[*] Waiting for VMs to be ready...")
        time.sleep(30)

        def run_single_baseline(vm_name: str, controller: CapeVMController, vm_config: Dict) -> Tuple[str, Optional[Dict]]:

            try:
                print(f"    [*] {vm_name}: Starting baseline submission...")

                controller.ssh_client.execute_command(
                    "rm -f /opt/CAPEv2/analyzer/windows/data/yara/*.yar",
                    check_return_code=False
                )
                time.sleep(5)

                task_id = controller.submit_sample(str(self.binary_path))
                if not task_id:
                    print(f"    [!] {vm_name}: Failed to submit sample")
                    return vm_name, None

                print(f"    [*] {vm_name}: Task submitted (ID: {task_id})")

                max_wait = 300
                elapsed = 0

                while elapsed < max_wait:
                    time.sleep(30)
                    elapsed += 30

                    try:
                        results = controller.get_results(task_id)
                        if results:
                            baseline_analysis = self._analyze_cape_results(results, task_id)
                            baseline_analysis['is_baseline'] = True
                            baseline_analysis['yara_rules_active'] = False
                            baseline_analysis['task_id'] = task_id
                            baseline_analysis['vm_name'] = vm_name

                            sig_count = len(baseline_analysis.get('signature_names', []))
                            print(f"    [+] {vm_name}: Baseline complete - {sig_count} signatures")
                            return vm_name, baseline_analysis
                    except Exception as e:
                        pass

                print(f"    [!] {vm_name}: Baseline timeout after {max_wait}s")
                return vm_name, None

            except Exception as e:
                print(f"    [!] {vm_name}: Baseline error - {e}")
                return vm_name, None

        print(f"\n[*] Submitting baseline to {len(vm_controllers)} VMs in parallel...")
        baseline_results = {}

        with ThreadPoolExecutor(max_workers=len(vm_controllers)) as executor:
            futures = {
                executor.submit(run_single_baseline, vm_name, controller, vm_config): vm_name
                for vm_name, (controller, vm_config) in vm_controllers.items()
            }

            for future in as_completed(futures):
                vm_name, result = future.result()
                baseline_results[vm_name] = result

        for vm_name, (controller, _) in vm_controllers.items():
            try:
                controller.close()
            except:
                pass

        print(f"\n[*] Selecting best baseline result...")
        best_baseline = None
        best_sig_count = -1
        best_vm = None

        for vm_name, result in baseline_results.items():
            if result is None:
                print(f"    [-] {vm_name}: Failed (no result)")
                continue

            sig_count = len(result.get('signature_names', []))
            print(f"    [+] {vm_name}: {sig_count} signatures")

            if sig_count > best_sig_count:
                best_sig_count = sig_count
                best_baseline = result
                best_vm = vm_name

        if best_baseline:
            print(f"\n[+] Selected baseline from {best_vm}: {best_sig_count} signatures")

            if best_sig_count == 0:
                print(f"    [*] Zero baseline signatures - malware likely evading sandbox")
                best_baseline['zero_baseline'] = True

            self.results['baseline_result'] = best_baseline
            self.results['baseline_all_vms'] = baseline_results
            return best_baseline
        else:
            print(f"\n[!] All VMs failed to produce baseline result")
            self.results['baseline_result'] = {
                'baseline_failed': True,
                'signature_names': [],
                'signature_count': 0
            }
            return None

    def validate_in_cape_multi_vm(self, yara_rules: List[Tuple[str, YaraResult]]) -> Dict:

        print(f"\n{'='*60}")
        print(f"PHASE 2: MULTI-VM PARALLEL CAPE VALIDATION")
        print(f"{'='*60}")

        if not self.binary_path:
            print("[!] No binary path specified - skipping CAPE validation")
            return {'validations': [], 'success_rate': 0, 'skipped': True}

        if not self._binary_exists():
            print(f"[!] Binary not found: {self.binary_path}")
            return {'validations': [], 'success_rate': 0, 'error': 'Binary not found'}

        print(f"[+] Binary: {self._get_binary_name()}")
        print(f"[+] YARA rules to test: {len(yara_rules)}")
        print(f"[+] VMs configured: {len(self.vm_configs)}")

        print(f"\n[*] Connecting to VMs...")
        self.vm_manager = MultiVMManager(self.vm_configs)
        connected = self.vm_manager.connect_all()

        if connected == 0:
            print("[!] No VMs connected - falling back to single VM mode")
            return self.validate_in_cape(yara_rules)

        print(f"[+] Connected to {connected} VMs")

        print(f"\n[*] Starting CAPE services on all VMs...")
        for vm_name, controller in self.vm_manager.vm_controllers.items():
            try:
                if controller.start_services():
                    print(f"    [+] Services started on {vm_name}")
                else:
                    print(f"    [!] Failed to start services on {vm_name}")
            except Exception as e:
                print(f"    [!] Error starting services on {vm_name}: {e}")

        print("[*] Waiting for VMs to be ready...")
        time.sleep(30)

        print(f"\n[*] Starting PARALLEL validation (baseline + YARA rules)...")
        validations = []
        pending_rules = list(yara_rules)
        baseline = None

        def run_baseline_task(vm_name: str, controller: CapeVMController, vm_config: Dict) -> Optional[Dict]:

            print(f"[*] VM1 ({vm_name}): Starting BASELINE (no YARA rules)...")
            return self.run_baseline(controller, vm_config)

        def validate_single_rule(vm_name: str, controller: CapeVMController,
                                 yara_file: str, yara_result: YaraResult) -> Dict:

            rule_name = Path(yara_file).stem
            validation = {
                'yara_file': yara_file,
                'prompt_version': yara_result.prompt_version,
                'pattern_type': yara_result.pattern_type,
                'confidence': yara_result.confidence,
                'vm_name': vm_name,
                'task_id': None,
                'success': False,
                'bypass_detected': False,
                'analysis_results': {}
            }

            try:
                controller.ssh_client.execute_command(
                    "rm -f /opt/CAPEv2/analyzer/windows/data/yara/*.yar",
                    check_return_code=False
                )

                with open(yara_file, 'r', encoding='utf-8') as f:
                    yara_content = f.read()

                if not controller.deploy_yara_rule(yara_content, "test_rule.yar"):
                    validation['error'] = "Failed to deploy YARA rule"
                    return validation

                time.sleep(10)

                task_id = controller.submit_sample(str(self.binary_path))
                if not task_id:
                    validation['error'] = "Failed to submit sample"
                    return validation

                validation['task_id'] = task_id

                max_wait = 300
                elapsed = 0

                while elapsed < max_wait:
                    time.sleep(30)
                    elapsed += 30

                    try:
                        results = controller.get_results(task_id)
                        if results:
                            validation['success'] = True
                            validation['analysis_results'] = self._analyze_cape_results(results, task_id)
                            validation['bypass_detected'] = validation['analysis_results'].get('evasion_bypassed', False)
                            break
                    except:
                        pass

                if not validation['success']:
                    validation['error'] = f"Analysis timeout after {max_wait}s"

            except Exception as e:
                validation['error'] = str(e)

            return validation

        with ThreadPoolExecutor(max_workers=len(self.vm_manager.vms)) as executor:
            futures = {}
            baseline_started = False

            while pending_rules or futures or (not baseline_started and connected > 0):
                while True:
                    vm_result = self.vm_manager.get_free_vm()
                    if not vm_result:
                        break

                    vm_name, controller = vm_result

                    if not baseline_started:
                        baseline_started = True
                        print(f"[*] {vm_name}: Starting BASELINE (no YARA rules)")

                        vm_config = next((c for c in self.vm_configs if c.get('name') == vm_name), None)

                        future = executor.submit(
                            run_baseline_task,
                            vm_name, controller, vm_config
                        )
                        futures[future] = (vm_name, '__BASELINE__')
                    elif pending_rules:
                        yara_file, yara_result = pending_rules.pop(0)
                        print(f"[*] {vm_name}: Starting YARA rule {Path(yara_file).stem}")

                        future = executor.submit(
                            validate_single_rule,
                            vm_name, controller, yara_file, yara_result
                        )
                        futures[future] = (vm_name, yara_file)
                    else:
                        self.vm_manager.release_vm(vm_name)
                        break

                completed = []
                for future in futures:
                    if future.done():
                        completed.append(future)

                for future in completed:
                    vm_name, task_info = futures.pop(future)
                    try:
                        if task_info == '__BASELINE__':
                            baseline = future.result()
                            if baseline:
                                print(f"    [+] ✅ {vm_name}: BASELINE complete - {len(baseline.get('signature_names', []))} signatures")
                            else:
                                print(f"    [!] {vm_name}: BASELINE failed")
                        else:
                            yara_file = task_info
                            validation = future.result()
                            validations.append(validation)

                            if validation['bypass_detected']:
                                print(f"    [+] ✅ {vm_name}: {Path(yara_file).stem} - BYPASS SUCCESSFUL")
                                analysis_results = validation.get('analysis_results', {})
                                self.results['successful_bypasses'].append({
                                    'yara_file': yara_file,
                                    'prompt_version': validation['prompt_version'],
                                    'task_id': validation['task_id'],
                                    'vm_name': vm_name,
                                    'new_signatures': analysis_results.get('signature_names', []),
                                    'new_signature_details': analysis_results.get('signatures', [])
                                })
                            elif validation['success']:
                                print(f"    [-] {vm_name}: {Path(yara_file).stem} - No bypass detected")
                            else:
                                print(f"    [!] {vm_name}: {Path(yara_file).stem} - Failed")

                    except Exception as e:
                        print(f"    [!] Error processing result from {vm_name}: {e}")

                    self.vm_manager.release_vm(vm_name)

                if futures and not completed:
                    time.sleep(5)

        self.vm_manager.close_all()

        if baseline:
            self._compare_with_baseline(baseline, validations)

        successful = sum(1 for v in validations if v['success'])
        bypasses = sum(1 for v in validations if v['bypass_detected'])
        total = len(validations)

        print(f"\n{'='*60}")
        print(f"MULTI-VM VALIDATION SUMMARY")
        print(f"{'='*60}")
        print(f"[+] VMs used: {connected}")
        print(f"[+] Rules tested: {total}")
        print(f"[+] Analyses completed: {successful}/{total}")
        print(f"[+] Successful bypasses: {bypasses}/{total}")

        if bypasses > 0:
            print(f"\n[+] ✅ WORKING BYPASSES:")
            for v in validations:
                if v['bypass_detected']:
                    print(f"    - {Path(v['yara_file']).name} ({v['prompt_version'].upper()}) on {v['vm_name']}")

        self.results['cape_validations'] = validations

        return {
            'validations': validations,
            'total': total,
            'successful_analyses': successful,
            'successful_bypasses': bypasses,
            'success_rate': (bypasses / total * 100) if total > 0 else 0,
            'baseline': baseline
        }

    def _compare_with_baseline(self, baseline: Dict, validations: List[Dict]):

        print(f"\n{'='*60}")
        print("BASELINE COMPARISON")
        print(f"{'='*60}")

        baseline_sigs = set(baseline.get('signature_names', []))
        baseline_api_calls = baseline.get('api_calls', 0)
        baseline_malscore = baseline.get('malscore', 0)

        comparison = {
            'baseline': {
                'signatures': len(baseline_sigs),
                'api_calls': baseline_api_calls,
                'malscore': baseline_malscore
            },
            'improvements': []
        }

        print(f"Baseline: {len(baseline_sigs)} signatures, {baseline_api_calls} API calls, malscore {baseline_malscore}")

        for validation in validations:
            if not validation.get('success'):
                continue

            analysis = validation.get('analysis_results', {})
            rule_sigs = set(analysis.get('signature_names', []))
            rule_api_calls = analysis.get('api_calls', 0)
            rule_malscore = analysis.get('malscore', 0)

            new_sigs = rule_sigs - baseline_sigs

            improvement = {
                'yara_file': validation['yara_file'],
                'prompt_version': validation['prompt_version'],
                'new_signatures': list(new_sigs),
                'signature_diff': len(rule_sigs) - len(baseline_sigs),
                'api_calls_diff': rule_api_calls - baseline_api_calls,
                'malscore_diff': rule_malscore - baseline_malscore,
                'is_improvement': len(new_sigs) > 0 or rule_api_calls > baseline_api_calls
            }

            comparison['improvements'].append(improvement)

            if improvement['is_improvement']:
                print(f"\n[+] {Path(validation['yara_file']).stem} ({validation['prompt_version'].upper()}):")
                print(f"    Signatures: {len(rule_sigs)} (+{improvement['signature_diff']})")
                print(f"    API calls: {rule_api_calls} (+{improvement['api_calls_diff']})")
                if new_sigs:
                    print(f"    NEW signatures: {', '.join(list(new_sigs)[:5])}")

        self.results['comparison'] = comparison

    def _restart_cape_services(self, vm_config: Dict) -> bool:

        vm_host = vm_config.get('host', 'unknown')
        print(f"\n{'='*60}")
        print(f"[!] CAPE VM + SERVICE RECOVERY for {vm_host}")
        print(f"{'='*60}")

        try:
            print(f"[*] Step 1: Attempting to stop existing services...")
            cape = CapeVMController(
                host=vm_config['host'],
                user=vm_config['user'],
                password=vm_config['password']
            )

            if cape.connect():
                print(f"[*] Connected - stopping services before VM restart...")
                cape.stop_services()
                time.sleep(5)
            else:
                print(f"[*] Cannot connect - proceeding with VM restart anyway...")

            print(f"\n[*] Step 2: Restarting VM...")
            if not cape.restart_vm():
                print(f"[!] VM restart failed for {vm_host}")
                return False

            print(f"[+] VM restarted and SSH reconnected")

            print(f"\n[*] Step 3: Ensuring clean service state...")
            cape.stop_services()
            time.sleep(10)

            print(f"\n[*] Step 4: Starting CAPE services...")
            if cape.start_services():
                print(f"[+] CAPE services started successfully on {vm_host}")
                cape.close()

                print(f"[*] Step 5: Waiting 60 seconds for services to stabilize...")
                time.sleep(60)

                print(f"\n{'='*60}")
                print(f"[+] VM + SERVICE RECOVERY COMPLETE for {vm_host}")
                print(f"{'='*60}")
                return True
            else:
                print(f"[!] Failed to start CAPE services on {vm_host}")
                cape.close()
                return False

        except Exception as e:
            print(f"[!] Error during VM/service recovery: {e}")
            import traceback
            traceback.print_exc()
            return False

    def _analyze_cape_results(self, results: Dict, task_id: str) -> Dict:

        analysis = {
            'task_id': task_id,
            'evasion_bypassed': False,
            'score': 0,
            'malscore': 0,
            'duration': 0,
            'signatures': [],
            'signature_names': [],
            'api_calls': 0,
            'indicators': [],
            'yara_compiled': False,
            'yara_hits': [],
            'analysis_log_checks': {}
        }

        report = results.get('report', {})
        if not report:
            return analysis

        info = report.get('info', {})
        analysis['score'] = info.get('score', 0)
        analysis['duration'] = info.get('duration', 0)

        analysis['malscore'] = report.get('malscore', 0)

        signatures = report.get('signatures', [])
        analysis['signatures'] = signatures
        analysis['signature_names'] = [sig.get('name', '') for sig in signatures]

        behavior = report.get('behavior', {})
        for proc in behavior.get('processes', []):
            analysis['api_calls'] += len(proc.get('calls', []))

        analysis_log = results.get('analysis_log', '')
        if analysis_log:
            analysis['analysis_log_checks'] = self._check_analysis_log(analysis_log)
            analysis['yara_compiled'] = analysis['analysis_log_checks'].get('yara_compiled', False)
            analysis['yara_hits'] = analysis['analysis_log_checks'].get('yara_hits', [])

        debugger_output = results.get('debugger_output', {})
        bypass_evidence = []
        for filename, content in debugger_output.items():
            if isinstance(content, str):
                if 'breakpoint' in content.lower():
                    bypass_evidence.append("Breakpoint hit")
                if any(action in content.lower() for action in ['skip', 'nop', 'jmp']):
                    bypass_evidence.append("CAPE action executed")

        if analysis['yara_compiled']:
            analysis['indicators'].append("✅ YARA rule compiled")
        else:
            analysis['indicators'].append("❌ YARA rule NOT compiled")

        if analysis['yara_hits']:
            analysis['indicators'].append(f"✅ YaraScan hits: {', '.join(analysis['yara_hits'][:3])}")
        else:
            analysis['indicators'].append("❌ No YaraScan hits")

        if analysis['duration'] > 30:
            analysis['indicators'].append("✅ Extended runtime (>30s)")
        else:
            analysis['indicators'].append("❌ Short runtime")

        if analysis['api_calls'] > 100:
            analysis['indicators'].append("✅ Many API calls (>100)")
        else:
            analysis['indicators'].append("❌ Few API calls")

        if analysis['malscore'] > 2:
            analysis['indicators'].append(f"✅ Malicious behavior (score: {analysis['malscore']})")

        if bypass_evidence:
            analysis['indicators'].append(f"✅ Debugger: {', '.join(bypass_evidence)}")

        evasion_sigs = [s for s in analysis['signature_names']
                       if any(word in s.lower() for word in ['evasion', 'anti', 'debug', 'sandbox'])]
        if not evasion_sigs:
            analysis['indicators'].append("✅ No evasion signatures")
        else:
            analysis['indicators'].append(f"⚠️ Evasion sigs: {', '.join(evasion_sigs[:2])}")

        positive = sum(1 for i in analysis['indicators'] if i.startswith("✅"))
        analysis['evasion_bypassed'] = (
            analysis['yara_compiled'] and
            len(analysis['yara_hits']) > 0 and
            positive >= 3
        )

        return analysis

    def _check_analysis_log(self, log_content: str) -> Dict:

        import re

        result = {
            'yara_compiled': False,
            'yara_compiled_count': 0,
            'yara_hits': [],
            'raw_matches': []
        }

        compiled_match = re.search(r'YaraInit:\s*Compiled\s+(\d+)\s+rule', log_content, re.IGNORECASE)
        if compiled_match:
            result['yara_compiled'] = True
            result['yara_compiled_count'] = int(compiled_match.group(1))
            result['raw_matches'].append(compiled_match.group(0))

        if 'Compiled rules saved to file' in log_content:
            result['yara_compiled'] = True
            result['raw_matches'].append('Compiled rules saved to file')

        hit_matches = re.findall(r'(?:Internal)?YaraScan hit:\s*(\S+)', log_content, re.IGNORECASE)
        if hit_matches:
            for hit in hit_matches:
                if hit not in result['yara_hits']:
                    result['yara_hits'].append(hit)
                    result['raw_matches'].append(f"YaraScan hit: {hit}")

        return result


    def _classify_signatures(self, all_sigs: set, baseline_sigs: set) -> Tuple[set, set]:

        new_sigs = all_sigs - baseline_sigs

        crash_sigs = {s for s in new_sigs
                     if s.lower() in IGNORED_SIGNATURES or 'crash' in s.lower()}

        meaningful_new_sigs = new_sigs - crash_sigs

        return meaningful_new_sigs, crash_sigs

    def _parse_llm_response(self, response: str) -> Dict:

        result = {}

        match = re.search(r'\*\*PATTERN_TYPE\*\*:\s*\[?([^\]\n\*]+)', response)
        if match:
            result['pattern_type'] = match.group(1).strip()

        match = re.search(r'\*\*OPCODES_GENERIC\*\*:\s*\[?([0-9A-Fa-f\s\?]+)', response)
        if match:
            result['opcodes_generic'] = match.group(1).strip()

        match = re.search(r'\*\*CONFIDENCE\*\*:\s*\[?(\d+)', response)
        if match:
            result['confidence'] = int(match.group(1))

        matches = re.findall(r'```yara\s*(rule\s+.+?)\s*```', response, re.DOTALL)
        if matches:
            yara_rule = None
            for candidate in reversed(matches):
                if '[6-20 bytes' not in candidate and '[DIFFERENT' not in candidate:
                    yara_rule = candidate.strip()
                    break

            if yara_rule is None:
                yara_rule = matches[-1].strip()

            result['yara_rule'] = yara_rule

        return result

    def _parse_feedback(self, analysis: str) -> Dict:

        result = {'suggestions': []}

        match = re.search(r'\*\*SUGGESTED_FIX\*\*:\s*([^\n\*]+)', analysis)
        if match:
            result['suggested_fix'] = match.group(1).strip()
            result['suggestions'].append(match.group(1).strip())

        match = re.search(r'\*\*NEW_OPCODES_GENERIC\*\*:\s*([^\n\*]+)', analysis)
        if match and 'KEEP_CURRENT' not in match.group(1):
            result['new_opcodes'] = match.group(1).strip()

        return result

    def _summarize_attempt(self, attempt: Optional[BypassAttempt]) -> str:

        if not attempt:
            return "No previous attempts"

        summary = f"""
Pattern Type: {attempt.pattern_type}
Confidence: {attempt.confidence}
Status: {attempt.status.value}
Rule Hit: {attempt.rule_hit}
New Signatures: {attempt.new_signatures}
Failure Reason: {attempt.failure_reason or 'N/A'}
"""
        if hasattr(attempt, 'improvement_suggestions') and attempt.improvement_suggestions:
            summary += "\n**Improvement Suggestions from Analysis:**\n"
            for i, suggestion in enumerate(attempt.improvement_suggestions, 1):
                summary += f"  {i}. {suggestion}\n"

        return summary

    def _analyze_and_evolve(self, attempt: BypassAttempt,
                            original_trace: str,
                            state: EvolutionState):

        crashed = attempt.status == BypassStatus.BYPASS_CRASHED
        crash_sigs = []
        if crashed and attempt.failure_reason:
            match = re.search(r'\[([^\]]+)\]', attempt.failure_reason)
            if match:
                crash_sigs = [s.strip().strip("'") for s in match.group(1).split(',')]

        if crashed:
            crash_analysis = """
**CRITICAL: The previous rule caused the program to CRASH!**

**ANALYSIS STEPS:**
1. Check the debugger log below - find the instruction that was matched and skipped
2. Compare with the original trace - is the matched instruction from our target trace?
3. If the matched instruction is NOT in our trace, the pattern is too generic and matched elsewhere
4. If the matched instruction IS in our trace, skipping it caused problems

**HOW TO FIX:**
- Find the crashed instruction in the debugger log
- Look for NEARBY instructions in the original trace that are safer to skip
- Generate a NEW pattern targeting those nearby instructions instead
- Add more context bytes to make the pattern more specific to our target location
"""
            if attempt.debugger_log:
                debugger_content = attempt.debugger_log
                if len(debugger_content) > 3000:
                    debugger_content = debugger_content[:3000] + "\n... (truncated)"

                crash_analysis += f"""

**DEBUGGER LOG (shows exactly what happened during execution):**
```
{debugger_content}
```

Analyze the debugger log above to understand:
- Which breakpoint was hit (if any)
- What address/instruction caused the crash
- The register state at crash time
- Use this information to fix the skip offset or pattern
"""
        else:
            crash_analysis = ""

        debugger_section = ""
        if not crashed and attempt.debugger_log:
            debugger_content = attempt.debugger_log
            if len(debugger_content) > 2000:
                debugger_content = debugger_content[:2000] + "\n... (truncated)"
            debugger_section = f"""

**DEBUGGER LOG (execution trace):**
```
{debugger_content}
```
"""

        if crashed:
            status_str = "CRASHED"
        elif attempt.status == BypassStatus.BYPASS_SUCCESS:
            status_str = "succeeded"
        else:
            status_str = "failed"

        prompt = FEEDBACK_ANALYSIS_PROMPT.format(
            original_trace=original_trace[:2000] + "..." if len(original_trace) > 2000 else original_trace,
            yara_rule=attempt.yara_rule,
            rule_hit=attempt.rule_hit,
            baseline_sigs=attempt.baseline_signatures,
            new_sigs=attempt.new_signatures,
            new_sig_names=attempt.new_signature_names,
            crashed=crashed,
            crash_sigs=crash_sigs,
            crash_analysis=crash_analysis,
            debugger_section=debugger_section,
            status=status_str
        )

        try:
            analysis = self.smart_orchestrator.call_llm(prompt)
            improvements = self._parse_feedback(analysis)
            attempt.improvement_suggestions = improvements.get('suggestions', [])
        except Exception as e:
            print(f"  [!] Evolution analysis error: {e}")

    def _generate_evolved_rule(self, sha256: str, trace: str,
                                prompt_version: str, iteration: int,
                                state: EvolutionState,
                                previous_rule: str = None,
                                validation_errors: List[str] = None) -> BypassAttempt:

        attempt = BypassAttempt(
            iteration=iteration,
            prompt_version=prompt_version,
            yara_rule="",
            pattern_type="",
            confidence=0,
            opcodes=""
        )

        is_validation_retry = previous_rule and validation_errors and len(validation_errors) > 0

        if is_validation_retry:
            print(f"    [*] Using self-correction retry prompt with {len(validation_errors)} error(s)")
            formatted_prompt = self.prompt_loader.format_retry_prompt(
                original_version=prompt_version,
                original_trace=trace,
                previous_rule=previous_rule,
                errors=validation_errors
            )
        elif iteration == 0:
            if self.pe2_enabled:
                current_prompt = self._pe2_get_current_prompt(prompt_version)
                formatted_prompt = current_prompt.replace("{{trace}}", trace)
                print(f"    [PE2] Using evolved prompt (history: {len(self.pe2_states.get(prompt_version, PE2State(prompt_version, '')).history)})")
            else:
                formatted_prompt = format_prompt(prompt_version, trace=trace)
        else:
            formatted_prompt = RULE_EVOLUTION_PROMPT.format(
                sha256=sha256[:16],
                evolution_history="\n".join(state.optimization_history[-5:]),
                best_rule=state.best_attempt.yara_rule if state.best_attempt else "None",
                best_score=state.best_score,
                latest_analysis=self._summarize_attempt(state.iterations[-1] if state.iterations else None),
                original_trace=trace[:3000] + "..." if len(trace) > 3000 else trace,
                iteration=iteration
            )

        if self.global_memory:
            formatted_prompt = f"{self.global_memory}\n\n{formatted_prompt}"

        try:
            self.eval_logger.start_llm_query(prompt_version=prompt_version)

            response = self.smart_orchestrator.call_llm(formatted_prompt)
            attempt.raw_response = response

            parsed = self._parse_llm_response(response)
            attempt.yara_rule = parsed.get('yara_rule', '')
            attempt.pattern_type = parsed.get('pattern_type', 'UNKNOWN')
            attempt.confidence = parsed.get('confidence', 50)
            attempt.opcodes = parsed.get('opcodes_generic', '')

            provider_info = self.smart_orchestrator.get_provider_info()
            self.eval_logger.log_llm_query(
                prompt_text=formatted_prompt,
                response_text=response,
                model_name=provider_info.get('model', 'unknown'),
                model_provider=provider_info.get('current_provider', 'unknown'),
                temperature=0.7,
                pattern_type=attempt.pattern_type,
                confidence=attempt.confidence,
                yara_rule=attempt.yara_rule,
                opcodes_generic=attempt.opcodes,
                opcodes_specific=parsed.get('opcodes_specific', ''),
                prompt_version=prompt_version
            )

            print(f"    Pattern: {attempt.pattern_type}")
            print(f"    Confidence: {attempt.confidence}")

        except Exception as e:
            print(f"    [!] LLM error: {e}")
            attempt.failure_reason = str(e)

        return attempt

    def _validate_attempt_in_cape(self, attempt: BypassAttempt,
                                   baseline_sig_names: set,
                                   vm_config: Optional[Dict] = None) -> BypassAttempt:

        if not attempt.yara_rule:
            attempt.status = BypassStatus.ERROR
            attempt.failure_reason = "No YARA rule to validate"
            return attempt

        is_valid, sanitized_rule, issues = sanitize_yara_rule(attempt.yara_rule, iteration=attempt.iteration)

        if issues:
            for issue in issues:
                if issue.startswith("Warning:"):
                    print(f"    [!] {issue}")
                else:
                    print(f"    [!] Validation: {issue}")

        if sanitized_rule and sanitized_rule != attempt.yara_rule:
            print(f"    [*] YARA rule was sanitized (fixed formatting/auto-injected cape_options)")
            attempt.yara_rule = sanitized_rule

        has_cape_options = 'cape_options' in attempt.yara_rule.lower()
        if not has_cape_options:
            attempt.status = BypassStatus.ERROR
            attempt.failure_reason = "Generated rule is a detection rule, not a bypass rule (missing cape_options)"
            print(f"    [!] Rule missing cape_options - not a bypass rule")
            yara_path = self.output_dir / f"iter{attempt.iteration}_{attempt.prompt_version}.yar"
            with open(yara_path, 'w', encoding='utf-8') as f:
                f.write(attempt.yara_rule)
            attempt.yara_file = str(yara_path)
            return attempt

        if not is_valid and has_cape_options:
            print(f"    [*] Rule has validation warnings but cape_options present - will attempt VM validation")

        yara_path = self.output_dir / f"iter{attempt.iteration}_{attempt.prompt_version}.yar"
        with open(yara_path, 'w', encoding='utf-8') as f:
            f.write(attempt.yara_rule)
        attempt.yara_file = str(yara_path)

        if vm_config is None:
            vm_config = self.vm_configs[0] if self.vm_configs else DEFAULT_VM_CONFIGS[0]

        cape = CapeVMController(
            host=vm_config['host'],
            user=vm_config['user'],
            password=vm_config['password']
        )

        if not cape.connect():
            attempt.status = BypassStatus.ERROR
            attempt.failure_reason = "Failed to connect to CAPE"
            return attempt

        try:
            cape.ssh_client.execute_command(
                "rm -f /opt/CAPEv2/analyzer/windows/data/yara/*.yar",
                check_return_code=False
            )

            if not cape.deploy_yara_rule(attempt.yara_rule, "test_rule.yar"):
                attempt.status = BypassStatus.ERROR
                attempt.failure_reason = "Failed to deploy YARA rule"
                cape.close()
                return attempt

            time.sleep(10)

            self.eval_logger.start_cape_analysis(prompt_version=attempt.prompt_version)

            task_id = cape.submit_sample(str(self.binary_path))
            if not task_id:
                attempt.status = BypassStatus.ERROR
                attempt.failure_reason = "Failed to submit sample"
                cape.close()
                return attempt

            attempt.task_id = task_id
            print(f"    [+] Submitted as task {task_id}")

            print("    [*] Waiting for analysis...")
            max_wait = 300
            elapsed = 0

            while elapsed < max_wait:
                time.sleep(30)
                elapsed += 30

                try:
                    results = cape.get_results(task_id)
                    if results:
                        analysis = self._analyze_cape_results(results, task_id)

                        attempt.rule_hit = (
                            analysis.get('yara_compiled', False) and
                            len(analysis.get('yara_hits', [])) > 0
                        )

                        all_sig_names = set(analysis.get('signature_names', []))
                        meaningful_new_sigs, crash_sigs = self._classify_signatures(
                            all_sig_names, baseline_sig_names
                        )

                        attempt.baseline_signatures = len(baseline_sig_names)
                        attempt.new_signatures = len(meaningful_new_sigs)
                        attempt.new_signature_names = list(meaningful_new_sigs)

                        all_signatures = analysis.get('signatures', [])
                        attempt.new_signature_details = [
                            sig for sig in all_signatures
                            if sig.get('name', '') in meaningful_new_sigs
                        ]

                        debugger_output = results.get('debugger_output', {})
                        if debugger_output:
                            debugger_logs = []
                            for filename, content in debugger_output.items():
                                if isinstance(content, str) and content.strip():
                                    debugger_logs.append(f"=== {filename} ===\n{content}")
                            if debugger_logs:
                                attempt.debugger_log = "\n\n".join(debugger_logs)
                                print(f"    [+] Captured debugger log ({len(attempt.debugger_log)} chars)")

                        if crash_sigs:
                            attempt.status = BypassStatus.BYPASS_CRASHED
                            attempt.failure_reason = f"Rule caused crash: {list(crash_sigs)}"
                            print(f"    [!] CRASH DETECTED: {list(crash_sigs)}")
                        elif attempt.rule_hit and attempt.new_signatures >= self.min_signature_improvement:
                            attempt.status = BypassStatus.BYPASS_SUCCESS
                        elif attempt.rule_hit:
                            attempt.status = BypassStatus.RULE_HIT
                            attempt.failure_reason = "Rule hit but no new signatures"
                        elif attempt.new_signatures >= self.min_signature_improvement:
                            attempt.status = BypassStatus.BYPASS_FAILED
                            attempt.failure_reason = "New signatures found but YARA rule did not match - likely coincidental"
                        else:
                            attempt.status = BypassStatus.BYPASS_FAILED
                            attempt.failure_reason = "YARA pattern did not match"

                        print(f"    Rule Hit: {attempt.rule_hit}")
                        print(f"    New Signatures (meaningful): {attempt.new_signatures}")
                        if crash_sigs:
                            print(f"    Crash Signatures (ignored): {list(crash_sigs)}")
                        if attempt.new_signature_names:
                            print(f"    Names: {attempt.new_signature_names[:3]}")

                        self.eval_logger.log_cape_analysis(
                            task_id=int(task_id) if task_id else 0,
                            analysis_type="bypass",
                            signatures=list(all_sig_names),
                            rule_hit=attempt.rule_hit,
                            yara_rule=attempt.yara_rule,
                            yara_file=attempt.yara_file,
                            prompt_version=attempt.prompt_version,
                            vm_host=vm_config.get('host') if vm_config else None,
                            vm_name=vm_config.get('name') if vm_config else None
                        )

                        break
                except Exception:
                    pass

                if elapsed % 60 == 0:
                    print(f"        Still waiting... ({elapsed}s)")

            if attempt.status == BypassStatus.PENDING:
                attempt.status = BypassStatus.ERROR
                attempt.failure_reason = f"Analysis timeout after {max_wait}s"

        except Exception as e:
            print(f"    [!] CAPE validation error: {e}")
            attempt.status = BypassStatus.ERROR
            attempt.failure_reason = str(e)

        cape.close()
        return attempt

    def evolve_prompt(self, sha256: str, prompt_version: str,
                       baseline_sig_names: set,
                       original_trace: str,
                       vm_config: Optional[Dict] = None) -> EvolutionState:

        if vm_config is None:
            vm_config = self.vm_configs[0] if self.vm_configs else DEFAULT_VM_CONFIGS[0]

        vm_host = vm_config.get('host', 'unknown')
        print(f"\n{'='*60}")
        print(f"EVOLVING PROMPT: {prompt_version.upper()} on VM {vm_host}")
        print(f"{'='*60}")
        print(f"Max Iterations: {self.max_iterations}")
        print(f"Success Criteria: >= {self.min_signature_improvement} new signature(s)")

        state = EvolutionState(
            sha256=sha256,
            prompt_version=prompt_version
        )

        start_iter = 0
        if self.continuation_state and self.continuation_state.get('prompt_version') == prompt_version:
            prev_history = self.continuation_state.get('evolution_history', [])
            state.optimization_history = prev_history.copy()
            state.successful_patterns = self.continuation_state.get('successful_patterns', []).copy()
            state.failed_patterns = self.continuation_state.get('failed_patterns', []).copy()
            state.best_score = self.continuation_state.get('best_score', 0)

            start_iter = self.start_iteration
            print(f"\n[Continue] Resuming from iteration {start_iter + 1}")
            print(f"[Continue] Previous evolution history ({len(prev_history)} entries):")
            for h in prev_history[-3:]:
                print(f"  - {h}")
            if len(prev_history) > 3:
                print(f"  ... and {len(prev_history) - 3} more")

        prompt_metadata = get_prompt_metadata(prompt_version)
        prompt_name = prompt_metadata.name if prompt_metadata else prompt_version
        self.eval_logger.start_prompt_strategy(prompt_version, prompt_name)

        consecutive_connection_failures = 0
        service_recovery_attempted = False

        for iteration in range(start_iter, self.max_iterations):
            print(f"\n[*] Iteration {iteration + 1}/{self.max_iterations}")

            self.eval_logger.start_iteration(iteration, prompt_version=prompt_version)

            max_generation_retries = self.max_retries if hasattr(self, 'max_retries') else 3
            attempt = None
            previous_rule = None
            validation_errors = None

            for gen_retry in range(max_generation_retries):
                attempt = self._generate_evolved_rule(
                    sha256=sha256,
                    trace=original_trace,
                    prompt_version=prompt_version,
                    iteration=iteration,
                    state=state,
                    previous_rule=previous_rule,
                    validation_errors=validation_errors if self.use_retry_feedback else None
                )

                if not attempt.yara_rule:
                    if gen_retry < max_generation_retries - 1:
                        print(f"    [!] Failed to generate YARA rule, retrying ({gen_retry + 1}/{max_generation_retries})...")
                        continue
                    else:
                        print("    [!] Failed to generate YARA rule after retries")
                        attempt.status = BypassStatus.ERROR
                        attempt.failure_reason = "Failed to generate YARA rule"
                        state.iterations.append(attempt)
                        break

                is_valid, sanitized_rule, issues = sanitize_yara_rule(attempt.yara_rule, iteration=iteration)

                actual_errors = [i for i in issues if not i.startswith("Warning:")]

                has_cape_options = 'cape_options' in (sanitized_rule or attempt.yara_rule).lower()

                if not has_cape_options:
                    actual_errors.append("Missing cape_options - not a bypass rule")

                if actual_errors and gen_retry < max_generation_retries - 1:
                    print(f"    [!] Rule validation failed ({len(actual_errors)} error(s)), self-correction retry ({gen_retry + 1}/{max_generation_retries})...")
                    for err in actual_errors[:3]:
                        print(f"        - {err}")
                    previous_rule = attempt.yara_rule
                    validation_errors = actual_errors
                    continue

                if sanitized_rule:
                    attempt.yara_rule = sanitized_rule

                break

            if not attempt.yara_rule:
                continue

            print(f"    [*] Validating rule in CAPE on {vm_host}...")
            attempt = self._validate_attempt_in_cape(attempt, baseline_sig_names, vm_config)

            vm_failure_reasons = ["Failed to connect to CAPE", "Failed to submit sample"]
            is_vm_failure = attempt.failure_reason in vm_failure_reasons

            if is_vm_failure:
                consecutive_connection_failures += 1
                print(f"    [!] VM failure #{consecutive_connection_failures}: {attempt.failure_reason}")

                if consecutive_connection_failures >= 2 and not service_recovery_attempted:
                    print(f"    [!] {consecutive_connection_failures} consecutive VM failures detected!")
                    service_recovery_attempted = True

                    if self._restart_cape_services(vm_config):
                        print(f"    [*] Retrying iteration {iteration + 1} after service recovery...")
                        attempt = self._validate_attempt_in_cape(attempt, baseline_sig_names, vm_config)

                        if attempt.failure_reason not in vm_failure_reasons:
                            consecutive_connection_failures = 0
                        else:
                            print(f"    [!] Still failing after service recovery: {attempt.failure_reason}")
                    else:
                        print(f"    [!] Service recovery failed, continuing with iterations...")
            else:
                consecutive_connection_failures = 0

            state.iterations.append(attempt)

            is_success = attempt.new_signatures >= self.min_signature_improvement
            self.eval_logger.log_iteration_result(
                success=is_success,
                new_signatures=attempt.new_signatures,
                new_signature_names=attempt.new_signature_names,
                feedback=attempt.failure_reason,
                evolution_reasoning=None,
                prompt_version=prompt_version
            )

            if attempt.new_signatures > state.best_score:
                state.best_score = attempt.new_signatures
                state.best_attempt = attempt
                print(f"    [+] NEW BEST! Found {attempt.new_signatures} new signature(s)")

            if attempt.new_signatures >= self.min_signature_improvement:
                print(f"\n    [+] SUCCESS at iteration {iteration + 1}!")
                print(f"        Found {attempt.new_signatures} new signature(s): {attempt.new_signature_names[:5]}")
                state.optimization_history.append(
                    f"Iteration {iteration + 1}: SUCCESS - {attempt.new_signatures} new signatures"
                )
                state.successful_patterns.append(attempt.opcodes)
                break

            print(f"    [*] Analyzing results and evolving...")
            self._analyze_and_evolve(attempt, original_trace, state)

            state.failed_patterns.append(attempt.opcodes)
            state.optimization_history.append(
                f"Iteration {iteration + 1}: {attempt.status.value} - {attempt.failure_reason}"
            )

        final_rule = state.best_attempt.yara_rule if state.best_attempt else None
        final_sigs = state.best_attempt.new_signature_names if state.best_attempt else []
        self.eval_logger.end_prompt_strategy(
            final_yara_rule=final_rule,
            final_new_signatures=final_sigs,
            prompt_version=prompt_version
        )

        return state

    def _save_evolution_state(self, state: EvolutionState):

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"evolution_{state.sha256[:16]}_{state.prompt_version}_{timestamp}.json"
        filepath = self.output_dir / filename

        data = {
            'sha256': state.sha256,
            'prompt_version': state.prompt_version,
            'iterations': [],
            'best_attempt': None,
            'best_score': state.best_score,
            'optimization_history': state.optimization_history,
            'successful_patterns': state.successful_patterns,
            'failed_patterns': state.failed_patterns
        }

        for attempt in state.iterations:
            attempt_dict = asdict(attempt)
            attempt_dict['status'] = attempt.status.value
            data['iterations'].append(attempt_dict)

        if state.best_attempt:
            best_dict = asdict(state.best_attempt)
            best_dict['status'] = state.best_attempt.status.value
            data['best_attempt'] = best_dict

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        print(f"    [+] Saved evolution state to: {filepath}")


    def run(self,
            sha256: str,
            prompt_versions: Optional[List[str]] = None) -> Dict:

        print(f"\n{'='*70}")
        print("SIMPLIFIED BYPASS PIPELINE" + (" (EVOLVING MODE)" if self.evolving_enabled else ""))
        print(f"{'='*70}")
        print(f"Sample: {sha256}")
        print(f"Binary: {self.binary_path}")
        print(f"Output: {self.output_dir}")
        if self.evolving_enabled:
            print(f"Max Iterations: {self.max_iterations}")
            print(f"Min Signature Improvement: {self.min_signature_improvement}")
        print(f"{'='*70}")

        if self.evolving_enabled:
            return self.run_evolving(sha256, prompt_versions)

        yara_rules = self.generate_yara_rules(sha256, prompt_versions)

        if not yara_rules:
            print("\n[!] No YARA rules generated - cannot proceed")
            self.save_results()
            return self.results

        if self.multi_vm_enabled:
            validation_results = self.validate_in_cape_multi_vm(yara_rules)
        else:
            validation_results = self.validate_in_cape(yara_rules)

        print(f"\n{'='*70}")
        print("PIPELINE COMPLETE")
        print(f"{'='*70}")
        print(f"[+] YARA rules generated: {len(yara_rules)}")
        print(f"[+] Successful bypasses: {len(self.results['successful_bypasses'])}")

        if self.results['successful_bypasses']:
            print(f"\n[+] ✅ WORKING BYPASS RULES:")
            for bypass in self.results['successful_bypasses']:
                print(f"    - {Path(bypass['yara_file']).name}")

        self.save_results()
        return self.results

    def run_evolving(self,
                     sha256: str,
                     prompt_versions: Optional[List[str]] = None) -> Dict:

        provider_info = self.smart_orchestrator.get_provider_info()
        eval_id = self.eval_logger.start_evaluation(
            sha256=sha256,
            sample_path=str(self.binary_path) if self.binary_path else None,
            model_name=provider_info.get('model', 'unknown'),
            model_provider=provider_info.get('current_provider', 'unknown'),
            temperature=0.7
        )
        print(f"[+] Evaluation ID: {eval_id}")

        if not self.trace_loader.sample_exists(sha256):
            print(f"[!] Sample not found: {sha256}")
            return self.results

        original_trace = self.trace_loader.get_all_traces_for_prompt(sha256)
        if not original_trace:
            print(f"[!] Could not load trace for: {sha256}")
            return self.results

        print(f"[+] Loaded ALL traces ({len(original_trace)} chars)")

        if prompt_versions:
            versions = prompt_versions
        else:
            versions = list(ALL_PROMPTS.keys())

        print(f"[+] Prompts to evolve: {', '.join(v.upper() for v in versions)}")

        print(f"\n[*] Getting baseline execution (no bypass)...")
        baseline_start_time = time.time()
        baseline = self._get_baseline_for_evolving()
        baseline_sig_names = set(baseline.get('signature_names', []))
        baseline_duration = time.time() - baseline_start_time
        print(f"[+] Baseline: {len(baseline_sig_names)} signatures")
        self.results['baseline_result'] = baseline

        self.eval_logger.log_baseline(
            task_id=baseline.get('task_id', 0),
            signatures=list(baseline_sig_names),
            duration_seconds=baseline_duration
        )

        overall_best_state = None
        overall_best_score = 0

        if self.multi_vm_enabled and len(self.vm_configs) > 1:
            print(f"\n[+] MULTI-VM EVOLUTION MODE: {len(self.vm_configs)} VMs available")
            for vm in self.vm_configs:
                print(f"    - {vm['host']}")

            all_states = []
            remaining_versions = list(versions)

            while remaining_versions:
                batch_size = min(len(remaining_versions), len(self.vm_configs))
                batch_versions = remaining_versions[:batch_size]
                remaining_versions = remaining_versions[batch_size:]

                print(f"\n[*] Evolving batch of {len(batch_versions)} prompts in parallel...")
                for i, v in enumerate(batch_versions):
                    print(f"    VM {self.vm_configs[i]['host']}: {v.upper()}")

                with ThreadPoolExecutor(max_workers=len(batch_versions)) as executor:
                    futures = {}
                    for i, version in enumerate(batch_versions):
                        vm_config = self.vm_configs[i]
                        future = executor.submit(
                            self.evolve_prompt,
                            sha256=sha256,
                            prompt_version=version,
                            baseline_sig_names=baseline_sig_names,
                            original_trace=original_trace,
                            vm_config=vm_config
                        )
                        futures[future] = (version, vm_config)

                    for future in as_completed(futures):
                        version, vm_config = futures[future]
                        try:
                            state = future.result()
                            all_states.append((version, state))

                            self._save_evolution_state(state)
                            self.results['evolution_states'][version] = {
                                'iterations': len(state.iterations),
                                'best_score': state.best_score,
                                'success': state.best_score >= self.min_signature_improvement,
                                'vm_host': vm_config['host']
                            }

                            if state.best_score > overall_best_score:
                                overall_best_score = state.best_score
                                overall_best_state = state

                            if state.best_attempt and state.best_score >= self.min_signature_improvement:
                                self.results['successful_bypasses'].append({
                                    'prompt_version': version,
                                    'yara_file': state.best_attempt.yara_file,
                                    'new_signatures': state.best_attempt.new_signature_names,
                                    'new_signature_details': state.best_attempt.new_signature_details,
                                    'iterations': len(state.iterations),
                                    'vm_host': vm_config['host']
                                })
                                print(f"\n[+] SUCCESS on VM {vm_config['host']} with {version.upper()}!")

                        except Exception as e:
                            print(f"[!] Error evolving {version} on {vm_config['host']}: {e}")
                            self.results['evolution_states'][version] = {
                                'iterations': 0,
                                'best_score': 0,
                                'success': False,
                                'error': str(e),
                                'vm_host': vm_config['host']
                            }

                if self.early_stop and any(state.best_score >= self.min_signature_improvement for _, state in all_states):
                    print(f"\n[+] Found working bypass! Stopping remaining batches.")
                    print(f"    (Use --no-early-stop to test all prompts)")
                    break

        else:
            for version in versions:
                state = self.evolve_prompt(
                    sha256=sha256,
                    prompt_version=version,
                    baseline_sig_names=baseline_sig_names,
                    original_trace=original_trace
                )

                self._save_evolution_state(state)
                self.results['evolution_states'][version] = {
                    'iterations': len(state.iterations),
                    'best_score': state.best_score,
                    'success': state.best_score >= self.min_signature_improvement
                }

                if state.best_score > overall_best_score:
                    overall_best_score = state.best_score
                    overall_best_state = state

                if state.best_attempt and state.best_score >= self.min_signature_improvement:
                    self.results['successful_bypasses'].append({
                        'prompt_version': version,
                        'yara_file': state.best_attempt.yara_file,
                        'new_signatures': state.best_attempt.new_signature_names,
                        'new_signature_details': state.best_attempt.new_signature_details,
                        'iterations': len(state.iterations)
                    })

                if self.pe2_enabled:
                    failure_examples = []
                    for attempt in state.iterations:
                        if attempt.status != BypassStatus.BYPASS_SUCCESS:
                            failure_examples.append({
                                'trace_summary': original_trace[:500],
                                'generated_rule': attempt.yara_rule[:500] if attempt.yara_rule else 'N/A',
                                'expected_location': 'Unknown',
                                'failure_reason': attempt.failure_reason or attempt.status.value
                            })

                    sample_accuracy = 100.0 if state.best_score >= self.min_signature_improvement else 0.0

                    if failure_examples:
                        self._pe2_evolve_prompt(version, failure_examples, sample_accuracy)

                if self.early_stop and state.best_score >= self.min_signature_improvement:
                    print(f"\n[+] Found working bypass with {version.upper()}!")
                    print(f"    Stopping early - no need to try other prompts")
                    print(f"    (Use --no-early-stop to test all prompts)")
                    break

        print(f"\n{'='*70}")
        print("EVOLUTION COMPLETE")
        print(f"{'='*70}")
        print(f"[+] Prompts evolved: {len(self.results['evolution_states'])}")
        print(f"[+] Best score: {overall_best_score} new signature(s)")
        print(f"[+] Successful bypasses: {len(self.results['successful_bypasses'])}")
        if self.multi_vm_enabled:
            print(f"[+] Mode: Multi-VM ({len(self.vm_configs)} VMs)")

        if self.pe2_enabled and self.pe2_states:
            print(f"\n[+] PE2 PROMPT EVOLUTION:")
            for version, pe2_state in self.pe2_states.items():
                print(f"    - {version.upper()}: {len(pe2_state.history)} evolutions")
                print(f"      Accuracy: {pe2_state.get_accuracy():.1f}%")
                print(f"      Momentum: {pe2_state.consecutive_improvements} consecutive improvements")

        if self.results['successful_bypasses']:
            print(f"\n[+] WORKING BYPASS RULES:")
            for bypass in self.results['successful_bypasses']:
                vm_info = f" (VM: {bypass.get('vm_host', 'N/A')})" if 'vm_host' in bypass else ""
                print(f"    - {bypass['prompt_version'].upper()}: {bypass['yara_file']}{vm_info}")
                print(f"      New signatures: {bypass['new_signatures'][:3]}")

        eval_output_path = self.eval_logger.end_evaluation()
        if eval_output_path:
            print(f"\n[+] Evaluation logs saved to: {eval_output_path}")

        self.save_results()
        return self.results

    def _get_baseline_for_evolving(self, vm_config: Optional[Dict] = None) -> Dict:

        if not self.binary_path or not self._binary_exists():
            return {'signature_names': [], 'signature_count': 0}

        if self.parallel_baseline:
            result = self.run_baseline_multi_vm()
            if result:
                return result
            else:
                return {'signature_names': [], 'signature_count': 0}

        if vm_config is None:
            vm_config = self.vm_configs[0] if self.vm_configs else DEFAULT_VM_CONFIGS[0]

        max_connection_retries = 2
        for connection_attempt in range(max_connection_retries + 1):
            cape = CapeVMController(
                host=vm_config['host'],
                user=vm_config['user'],
                password=vm_config['password']
            )

            if cape.connect():
                break

            print(f"[!] Failed to connect to CAPE for baseline (attempt {connection_attempt + 1}/{max_connection_retries + 1})")

            if connection_attempt == 1:
                print("[!] Attempting CAPE service recovery for baseline...")
                if self._restart_cape_services(vm_config):
                    continue
                else:
                    return {'signature_names': [], 'signature_count': 0}

            if connection_attempt == max_connection_retries:
                return {'signature_names': [], 'signature_count': 0}

        if not cape.start_services():
            cape.close()
            return {'signature_names': [], 'signature_count': 0}

        print("[*] Waiting for CAPE to be ready...")
        time.sleep(30)

        try:
            cape.ssh_client.execute_command(
                "rm -f /opt/CAPEv2/analyzer/windows/data/yara/*.yar",
                check_return_code=False
            )
            time.sleep(5)

            task_id = cape.submit_sample(str(self.binary_path))
            if not task_id:
                cape.close()
                return {'signature_names': [], 'signature_count': 0}

            print(f"[+] Baseline task ID: {task_id}")

            max_wait = 300
            elapsed = 0
            while elapsed < max_wait:
                time.sleep(30)
                elapsed += 30

                try:
                    results = cape.get_results(task_id)
                    if results:
                        report = results.get('report', {})
                        signatures = report.get('signatures', [])
                        sig_names = [s.get('name', '') for s in signatures]

                        cape.close()
                        return {
                            'task_id': task_id,
                            'signature_names': sig_names,
                            'signature_count': len(sig_names)
                        }
                except Exception:
                    pass

                if elapsed % 60 == 0:
                    print(f"    Still waiting... ({elapsed}s)")

            cape.close()
            return {'signature_names': [], 'signature_count': 0}

        except Exception as e:
            print(f"[!] Baseline error: {e}")
            cape.close()
            return {'signature_names': [], 'signature_count': 0}

    def run_all(self,
                binary_dir: Optional[str] = None,
                prompt_versions: Optional[List[str]] = None) -> Dict[str, Dict]:

        samples = self.list_available_samples()
        if not samples:
            print("[!] No samples found")
            return {}

        all_results = {}

        for i, sha256 in enumerate(samples):
            print(f"\n[{i+1}/{len(samples)}] Processing {sha256[:16]}...")

            if binary_dir:
                if binary_dir.startswith('/'):
                    binary_candidates = [
                        f"{binary_dir}/{sha256}",
                        f"{binary_dir}/{sha256}.exe",
                        f"{binary_dir}/{sha256}.bin",
                    ]
                    self.binary_path = f"{binary_dir}/{sha256}"
                    self.is_linux_binary_path = True
                else:
                    binary_candidates = [
                        Path(binary_dir) / sha256,
                        Path(binary_dir) / f"{sha256}.exe",
                        Path(binary_dir) / f"{sha256}.bin",
                    ]
                    for candidate in binary_candidates:
                        if candidate.exists():
                            self.binary_path = candidate
                            self.is_linux_binary_path = False
                            break

            if self.binary_path and self._binary_exists():
                result = self.run(sha256, prompt_versions)
                all_results[sha256] = result
            else:
                print(f"    [!] Binary not found for {sha256[:16]}")
                yara_rules = self.generate_yara_rules(sha256, prompt_versions)
                all_results[sha256] = {
                    'yara_rules': len(yara_rules),
                    'validated': False
                }

        return all_results

    def save_results(self):

        results_file = self.output_dir / "pipeline_results.json"
        with open(results_file, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False, default=str)
        print(f"\n[+] Results saved: {results_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Simplified Bypass Pipeline - Generate YARA rules and validate in CAPE"
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--sha256', help='SHA256 hash of sample to process')
    group.add_argument('--all', action='store_true', help='Process all available samples')
    group.add_argument('--list', action='store_true', help='List available samples')

    parser.add_argument('--binary', help='Path to malware binary for CAPE validation')
    parser.add_argument('--binary-dir', help='Directory with binaries (for --all mode)')

    parser.add_argument('--prompts', help='Comma-separated list of prompt versions (v1-v7)')
    parser.add_argument('--recommended', action='store_true',
                       help='Use only recommended prompt (V7)')

    parser.add_argument('--cape-host', default='192.168.52.144', help='CAPE VM host (single VM mode)')
    parser.add_argument('--cape-user', default='cape', help='CAPE VM user')
    parser.add_argument('--cape-password', default='12345', help='CAPE VM password')

    parser.add_argument('--multi-vm', action='store_true',
                       help='Enable multi-VM parallel validation (uses 3 VMs)')
    parser.add_argument('--vm-hosts', help='Comma-separated VM hosts for multi-VM mode (e.g., 192.168.52.144,192.168.52.145,192.168.52.146)')
    parser.add_argument('--parallel-baseline', action='store_true',
                       help='Run baseline on ALL VMs in parallel and pick result with most signatures (handles VM crashes/issues)')

    parser.add_argument('--evolving', action='store_true',
                       help='Enable self-evolving mode: iterate on each prompt until success')
    parser.add_argument('--max-iterations', type=int, default=5,
                       help='Maximum evolution iterations per prompt (default: 5)')
    parser.add_argument('--min-sig-improvement', type=int, default=1,
                       help='Minimum new signatures to count as success (default: 1)')
    parser.add_argument('--no-early-stop', action='store_true',
                       help='Disable early stopping - test ALL prompts even after finding success (for research/comparison)')
    parser.add_argument('--pe2', action='store_true',
                       help='Enable PE2 (Prompt Engineering a Prompt Engineer): evolve the prompt strategy itself based on feedback')

    parser.add_argument('--no-retry', action='store_true',
                       help='Disable pre-VM retry on validation errors')
    parser.add_argument('--max-retries', type=int, default=3,
                       help='Maximum retry attempts for validation errors (default: 3)')
    parser.add_argument('--retry-feedback', action='store_true', default=True,
                       help='Include error feedback in retry prompts (default: True)')
    parser.add_argument('--no-retry-feedback', action='store_true',
                       help='Disable error feedback in retry prompts')

    parser.add_argument('--continue-from', type=str, default=None,
                       help='Path to a strategy_vX.json file to continue from (loads previous evolution state)')
    parser.add_argument('--start-iteration', type=int, default=0,
                       help='Starting iteration number (0-based, used with --continue-from)')

    parser.add_argument('--llm-type', default='auto',
                       choices=['auto', 'openai', 'anthropic', 'ollama', 'api_only', 'local_only', 'manual'],
                       help='LLM provider')
    parser.add_argument('--model', help='Specific model to use')
    parser.add_argument('--api-key', help='API key for LLM provider')

    parser.add_argument('--trace-dir', help='Path to binary_trace folder')
    parser.add_argument('--output-dir', help='Path to output folder')

    args = parser.parse_args()

    if args.api_key:
        if args.llm_type == 'openai':
            os.environ['OPENAI_API_KEY'] = args.api_key
        elif args.llm_type == 'anthropic':
            os.environ['ANTHROPIC_API_KEY'] = args.api_key

    agent_config = {}
    if args.model:
        if 'gpt' in args.model.lower():
            agent_config['openai_model'] = args.model
        elif 'claude' in args.model.lower():
            agent_config['anthropic_model'] = args.model
        else:
            agent_config['ollama_model'] = args.model

    if args.multi_vm or args.vm_hosts:
        if args.vm_hosts:
            hosts = [h.strip() for h in args.vm_hosts.split(',')]
            vm_configs = [
                {'name': f'cape_vm{i+1}', 'host': host, 'user': args.cape_user, 'password': args.cape_password, 'active': True}
                for i, host in enumerate(hosts)
            ]
        else:
            vm_configs = [
                {'name': vm['name'], 'host': vm['host'], 'user': args.cape_user, 'password': args.cape_password, 'active': True}
                for vm in DEFAULT_VM_CONFIGS
            ]
        multi_vm = True
    else:
        vm_configs = [{'name': 'cape_vm1', 'host': args.cape_host, 'user': args.cape_user, 'password': args.cape_password, 'active': True}]
        multi_vm = False

    prompt_versions = None
    if args.prompts:
        prompt_versions = [v.strip().lower() for v in args.prompts.split(',')]
        available = list(ALL_PROMPTS.keys())
        for v in prompt_versions:
            if v not in available:
                print(f"[!] Unknown prompt version: {v}")
                print(f"[!] Available: {', '.join(available)}")
                return 1
    elif args.recommended:
        prompt_versions = [RECOMMENDED_PROMPT]

    if args.list:
        pipeline = SimplifiedBypassPipeline(
            trace_dir=args.trace_dir
        )
        pipeline.list_available_samples()
        return 0

    retry_on_error = not args.no_retry
    use_retry_feedback = not args.no_retry_feedback if hasattr(args, 'no_retry_feedback') else True

    pipeline = SimplifiedBypassPipeline(
        binary_path=args.binary,
        llm_type=args.llm_type,
        agent_config=agent_config if agent_config else None,
        vm_configs=vm_configs,
        trace_dir=args.trace_dir,
        output_dir=args.output_dir,
        multi_vm=multi_vm,
        evolving=args.evolving,
        max_iterations=args.max_iterations,
        min_signature_improvement=args.min_sig_improvement,
        early_stop=not args.no_early_stop,
        pe2_enabled=args.pe2,
        retry_on_error=retry_on_error,
        max_retries=args.max_retries,
        use_retry_feedback=use_retry_feedback,
        parallel_baseline=args.parallel_baseline,
        continue_from=args.continue_from,
        start_iteration=args.start_iteration
    )

    if args.sha256:
        pipeline.run(args.sha256, prompt_versions)
    elif args.all:
        pipeline.run_all(args.binary_dir, prompt_versions)

    return 0


if __name__ == "__main__":
    sys.exit(main())