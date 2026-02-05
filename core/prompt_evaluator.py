
import re
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict


@dataclass
class YaraResult:

    prompt_version: str
    pattern_type: str
    opcodes: str
    opcodes_generic: Optional[str]
    skip_offset: int
    confidence: int
    reasoning: str
    yara_rule: str
    raw_response: str
    parse_success: bool
    error_message: Optional[str]


@dataclass
class EvaluationResult:

    sha256: str
    timestamp: str
    prompt_results: Dict[str, YaraResult]
    best_prompt: str
    best_confidence: int
    all_agree: bool
    pattern_consensus: Optional[str]


class ResponseParser:


    @staticmethod
    def parse_response(response: str, prompt_version: str) -> YaraResult:

        try:
            pattern_type = ResponseParser._extract_field(
                response,
                ['PATTERN_FOUND', 'PATTERN_TYPE', 'PATTERN_FAMILY'],
                'UNKNOWN'
            )

            opcodes = ResponseParser._extract_opcodes(response)
            opcodes_generic = ResponseParser._extract_generic_opcodes(response)

            skip_offset = ResponseParser._extract_skip_offset(response)

            confidence = ResponseParser._extract_confidence(response)

            reasoning = ResponseParser._extract_field(
                response,
                ['REASONING', 'Reasoning'],
                ''
            )

            yara_rule = ResponseParser._extract_yara_rule(response)

            return YaraResult(
                prompt_version=prompt_version,
                pattern_type=pattern_type,
                opcodes=opcodes,
                opcodes_generic=opcodes_generic,
                skip_offset=skip_offset,
                confidence=confidence,
                reasoning=reasoning,
                yara_rule=yara_rule,
                raw_response=response,
                parse_success=bool(opcodes and yara_rule),
                error_message=None
            )

        except Exception as e:
            return YaraResult(
                prompt_version=prompt_version,
                pattern_type="ERROR",
                opcodes="",
                opcodes_generic=None,
                skip_offset=0,
                confidence=0,
                reasoning="",
                yara_rule="",
                raw_response=response,
                parse_success=False,
                error_message=str(e)
            )

    @staticmethod
    def _extract_field(text: str, field_names: List[str], default: str) -> str:

        for field in field_names:
            patterns = [
                rf'{field}:\s*\[?([^\]\n]+)\]?',
                rf'\*\*{field}\*\*:\s*\[?([^\]\n]+)\]?',
            ]
            for pattern in patterns:
                match = re.search(pattern, text, re.IGNORECASE)
                if match:
                    return match.group(1).strip()
        return default

    @staticmethod
    def _extract_opcodes(text: str) -> str:

        patterns = [
            r'OPCODES:\s*\[?([0-9A-Fa-f\s\?]+)\]?',
            r'OPCODES_SPECIFIC:\s*\[?([0-9A-Fa-f\s\?]+)\]?',
            r'\$pattern\s*=\s*\{\s*([0-9A-Fa-f\s\?]+)\s*\}',
        ]

        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                opcodes = match.group(1).strip()
                opcodes = re.sub(r'[^\dA-Fa-f\s\?]', '', opcodes)
                if len(opcodes) >= 4:
                    return opcodes

        yara_match = re.search(r'\$pattern\s*=\s*\{([^}]+)\}', text)
        if yara_match:
            opcodes = yara_match.group(1).strip()
            opcodes = re.sub(r'[^\dA-Fa-f\s\?]', '', opcodes)
            if len(opcodes) >= 4:
                return opcodes

        return ""

    @staticmethod
    def _extract_generic_opcodes(text: str) -> Optional[str]:

        patterns = [
            r'OPCODES_GENERIC:\s*\[?([0-9A-Fa-f\s\?]+)\]?',
            r'\$pattern_generic\s*=\s*\{\s*([0-9A-Fa-f\s\?]+)\s*\}',
        ]

        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1).strip()

        return None

    @staticmethod
    def _extract_skip_offset(text: str) -> int:

        patterns = [
            r'SKIP_OFFSET:\s*\+?(\d+)',
            r'offset\s*=?\s*\+?(\d+)',
            r'bp0=\$pattern\+(\d+)',
        ]

        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return int(match.group(1))

        return 0

    @staticmethod
    def _extract_confidence(text: str) -> int:

        patterns = [
            r'CONFIDENCE:\s*\[?(\d+)\]?(?:/100)?',
            r'confidence\s*=\s*"?(\d+)"?',
            r'Confidence:\s*(\d+)%?',
        ]

        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                conf = int(match.group(1))
                if conf > 100:
                    conf = 100
                return conf

        return 50

    @staticmethod
    def _extract_yara_rule(text: str) -> str:

        patterns = [
            r'```yara\s*(rule\s+.+?)\s*```',
            r'```\s*(rule\s+.+?)\s*```',
            r'(rule\s+\w+\s*\{[^}]+strings:[^}]+\})',
        ]

        for pattern in patterns:
            match = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
            if match:
                rule = match.group(1).strip()
                return ResponseParser._normalize_yara_hex_patterns(rule)

        return ""

    @staticmethod
    def _normalize_yara_hex_patterns(yara_rule: str) -> str:

        def normalize_token(token: str) -> list:

            if not token:
                return []

            if len(token) == 2:
                return [token.upper()]

            result = []
            i = 0
            while i < len(token):
                if token[i] == '?':
                    if i + 1 < len(token) and token[i + 1] == '?':
                        result.append('??')
                        i += 2
                    else:
                        result.append('?')
                        i += 1
                elif token[i] in '0123456789ABCDEFabcdef':
                    if i + 1 < len(token):
                        next_char = token[i + 1]
                        if next_char in '0123456789ABCDEFabcdef':
                            result.append(token[i:i + 2].upper())
                            i += 2
                        elif next_char == '?':
                            result.append(token[i].upper() + '?')
                            i += 2
                        else:
                            result.append(token[i].upper())
                            i += 1
                    else:
                        result.append(token[i].upper())
                        i += 1
                else:
                    i += 1

            return result

        def normalize_hex_string(match):

            hex_content = match.group(1).strip()

            tokens = hex_content.split()

            normalized = []
            for token in tokens:
                normalized.extend(normalize_token(token))

            if not normalized:
                return match.group(0)

            return '{ ' + ' '.join(normalized) + ' }'

        result = re.sub(
            r'\{\s*([0-9A-Fa-f\?\s]+)\s*\}',
            normalize_hex_string,
            yara_rule
        )

        return result


class PromptEvaluator:


    def __init__(self, llm_orchestrator, output_dir: Optional[str] = None):

        self.llm = llm_orchestrator
        self.parser = ResponseParser()

        if output_dir:
            self.output_dir = Path(output_dir)
        else:
            self.output_dir = Path(__file__).parent.parent / "evaluation_results"

        self.output_dir.mkdir(parents=True, exist_ok=True)

        from prompt_strategies import ALL_PROMPTS, get_prompt_metadata
        self.all_prompts = ALL_PROMPTS
        self.get_metadata = get_prompt_metadata

    def evaluate_single_prompt(self, trace: str, prompt_version: str) -> YaraResult:

        from prompt_strategies import format_prompt

        formatted_prompt = format_prompt(prompt_version, trace)

        print(f"[*] Evaluating prompt {prompt_version.upper()}...")
        try:
            response = self.llm.call_llm(formatted_prompt)
        except Exception as e:
            return YaraResult(
                prompt_version=prompt_version,
                pattern_type="ERROR",
                opcodes="",
                opcodes_generic=None,
                skip_offset=0,
                confidence=0,
                reasoning="",
                yara_rule="",
                raw_response=str(e),
                parse_success=False,
                error_message=f"LLM call failed: {e}"
            )

        result = self.parser.parse_response(response, prompt_version)

        metadata = self.get_metadata(prompt_version)
        print(f"    Pattern: {result.pattern_type}")
        print(f"    Confidence: {result.confidence}")
        print(f"    Parse success: {result.parse_success}")

        return result

    def evaluate_single_prompt_with_retry(self, trace: str, prompt_version: str,
                                          max_retries: int = 3,
                                          use_feedback: bool = True) -> Tuple[YaraResult, List[Dict]]:

        from prompt_strategies.prompt_loader import get_loader
        from core.yara_validator import YaraBypassValidator

        loader = get_loader()
        validator = YaraBypassValidator()

        attempt_summaries = []
        best_result = None
        previous_rule = None
        previous_errors = []

        for attempt in range(1, max_retries + 1):
            print(f"\n    [Retry {attempt}/{max_retries}] Generating with {prompt_version.upper()}")

            if attempt == 1 or not use_feedback or not previous_errors:
                result = self.evaluate_single_prompt(trace, prompt_version)
            else:
                print(f"        [*] Self-correction with {len(previous_errors)} error(s) as feedback")
                retry_prompt = loader.format_retry_prompt(
                    original_version=prompt_version,
                    original_trace=trace,
                    previous_rule=previous_rule or "",
                    errors=previous_errors
                )

                try:
                    response = self.llm.call_llm(retry_prompt)
                    result = self.parser.parse_response(response, prompt_version)
                except Exception as e:
                    result = YaraResult(
                        prompt_version=prompt_version,
                        pattern_type="ERROR",
                        opcodes="",
                        opcodes_generic=None,
                        skip_offset=0,
                        confidence=0,
                        reasoning="",
                        yara_rule="",
                        raw_response=str(e),
                        parse_success=False,
                        error_message=f"LLM call failed: {e}"
                    )

            validation_errors = []
            if result.parse_success and result.yara_rule:
                validation_result = validator.validate(result.yara_rule)

                if validation_result.is_valid:
                    print(f"        [+] Valid YARA rule - ready for VM submission")
                    attempt_summaries.append({
                        'attempt': attempt,
                        'success': True,
                        'errors': [],
                        'rule_preview': result.yara_rule[:100] + "..." if len(result.yara_rule) > 100 else result.yara_rule
                    })
                    return result, attempt_summaries
                else:
                    validation_errors = validation_result.errors
                    print(f"        [!] Validation failed: {len(validation_errors)} error(s)")
                    for err in validation_errors[:3]:
                        print(f"            - {err}")
            else:
                validation_errors = [result.error_message or "Failed to parse LLM response"]
                print(f"        [!] Parse failed: {result.error_message}")

            attempt_summaries.append({
                'attempt': attempt,
                'success': False,
                'errors': validation_errors,
                'rule_preview': (result.yara_rule[:100] + "...") if result.yara_rule and len(result.yara_rule) > 100 else (result.yara_rule or "No rule")
            })

            previous_rule = result.yara_rule
            previous_errors = validation_errors

            if best_result is None or (result.parse_success and not best_result.parse_success):
                best_result = result

        print(f"        [!] All {max_retries} retry attempts exhausted - rule may be invalid")
        return best_result or result, attempt_summaries

    def evaluate_all_prompts(self, trace: str, sha256: str = "unknown",
                            versions: Optional[List[str]] = None) -> EvaluationResult:

        if versions is None:
            versions = list(self.all_prompts.keys())

        prompt_results = {}
        best_prompt = ""
        best_confidence = 0

        for version in versions:
            result = self.evaluate_single_prompt(trace, version)
            prompt_results[version] = result

            if result.confidence > best_confidence and result.parse_success:
                best_confidence = result.confidence
                best_prompt = version

        all_agree, consensus = self._check_consensus(prompt_results)

        return EvaluationResult(
            sha256=sha256,
            timestamp=datetime.now().isoformat(),
            prompt_results=prompt_results,
            best_prompt=best_prompt,
            best_confidence=best_confidence,
            all_agree=all_agree,
            pattern_consensus=consensus
        )

    def evaluate_selected_prompts(self, trace: str, sha256: str,
                                  versions: List[str]) -> EvaluationResult:

        return self.evaluate_all_prompts(trace, sha256, versions)

    def _check_consensus(self, results: Dict[str, YaraResult]) -> Tuple[bool, Optional[str]]:

        successful_results = [r for r in results.values() if r.parse_success]

        if not successful_results:
            return False, None

        pattern_types = [r.pattern_type for r in successful_results]
        unique_patterns = set(pattern_types)

        if len(unique_patterns) == 1:
            return True, pattern_types[0]
        else:
            from collections import Counter
            most_common = Counter(pattern_types).most_common(1)[0][0]
            agreement_rate = pattern_types.count(most_common) / len(pattern_types)
            if agreement_rate >= 0.7:
                return True, most_common

        return False, None

    def get_best_result(self, evaluation: EvaluationResult) -> Optional[YaraResult]:

        if evaluation.best_prompt:
            return evaluation.prompt_results.get(evaluation.best_prompt)
        return None

    def generate_report(self, evaluation: EvaluationResult) -> str:

        lines = []
        lines.append("# Prompt Evaluation Report")
        lines.append(f"\n**Sample**: `{evaluation.sha256}`")
        lines.append(f"**Timestamp**: {evaluation.timestamp}")
        lines.append(f"**Best Prompt**: {evaluation.best_prompt.upper()}")
        lines.append(f"**Best Confidence**: {evaluation.best_confidence}%")
        lines.append(f"**Consensus**: {'Yes' if evaluation.all_agree else 'No'}")
        if evaluation.pattern_consensus:
            lines.append(f"**Consensus Pattern**: {evaluation.pattern_consensus}")

        lines.append("\n## Results by Prompt Version\n")
        lines.append("| Version | Pattern | Confidence | Parse OK | Opcodes |")
        lines.append("|---------|---------|------------|----------|---------|")

        for version in sorted(evaluation.prompt_results.keys()):
            result = evaluation.prompt_results[version]
            opcodes_short = result.opcodes[:20] + "..." if len(result.opcodes) > 20 else result.opcodes
            lines.append(
                f"| {version.upper()} | {result.pattern_type} | "
                f"{result.confidence}% | {'✓' if result.parse_success else '✗'} | "
                f"`{opcodes_short}` |"
            )

        lines.append("\n## Detailed Results\n")

        for version in sorted(evaluation.prompt_results.keys()):
            result = evaluation.prompt_results[version]
            lines.append(f"### {version.upper()}")
            lines.append(f"- **Pattern Type**: {result.pattern_type}")
            lines.append(f"- **Confidence**: {result.confidence}%")
            lines.append(f"- **Skip Offset**: +{result.skip_offset}")
            lines.append(f"- **Parse Success**: {result.parse_success}")

            if result.reasoning:
                lines.append(f"- **Reasoning**: {result.reasoning}")

            if result.yara_rule:
                lines.append("\n**YARA Rule**:")
                lines.append("```yara")
                lines.append(result.yara_rule)
                lines.append("```")

            lines.append("")

        return "\n".join(lines)

    def save_evaluation(self, evaluation: EvaluationResult, filename: Optional[str] = None):

        if not filename:
            filename = f"eval_{evaluation.sha256[:16]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        json_file = self.output_dir / f"{filename}.json"
        with open(json_file, 'w', encoding='utf-8') as f:
            data = {
                'sha256': evaluation.sha256,
                'timestamp': evaluation.timestamp,
                'best_prompt': evaluation.best_prompt,
                'best_confidence': evaluation.best_confidence,
                'all_agree': evaluation.all_agree,
                'pattern_consensus': evaluation.pattern_consensus,
                'prompt_results': {
                    k: asdict(v) for k, v in evaluation.prompt_results.items()
                }
            }
            json.dump(data, f, indent=2, ensure_ascii=False)

        md_file = self.output_dir / f"{filename}.md"
        report = self.generate_report(evaluation)
        with open(md_file, 'w', encoding='utf-8') as f:
            f.write(report)

        print(f"[+] Saved evaluation to {json_file}")
        print(f"[+] Saved report to {md_file}")

        return json_file, md_file


class BatchEvaluator:


    def __init__(self, llm_orchestrator, trace_loader, output_dir: Optional[str] = None):
        self.evaluator = PromptEvaluator(llm_orchestrator, output_dir)
        self.trace_loader = trace_loader

    def evaluate_all_samples(self, versions: Optional[List[str]] = None) -> Dict[str, EvaluationResult]:

        samples = self.trace_loader.list_samples()
        results = {}

        print(f"[*] Evaluating {len(samples)} samples...")

        for i, sha256 in enumerate(samples):
            print(f"\n[{i+1}/{len(samples)}] Processing {sha256[:16]}...")

            trace = self.trace_loader.get_all_traces_for_prompt(sha256)
            if not trace:
                print(f"  [!] Could not load trace")
                continue

            evaluation = self.evaluator.evaluate_all_prompts(trace, sha256, versions)
            results[sha256] = evaluation

            self.evaluator.save_evaluation(evaluation)

        return results

    def generate_summary_report(self, results: Dict[str, EvaluationResult]) -> str:

        lines = []
        lines.append("# Batch Evaluation Summary")
        lines.append(f"\n**Total Samples**: {len(results)}")
        lines.append(f"**Timestamp**: {datetime.now().isoformat()}")

        best_prompt_counts = {}
        for eval_result in results.values():
            bp = eval_result.best_prompt
            best_prompt_counts[bp] = best_prompt_counts.get(bp, 0) + 1

        lines.append("\n## Best Prompt Distribution\n")
        lines.append("| Prompt | Count | Percentage |")
        lines.append("|--------|-------|------------|")
        for prompt, count in sorted(best_prompt_counts.items(), key=lambda x: -x[1]):
            pct = count / len(results) * 100
            lines.append(f"| {prompt.upper()} | {count} | {pct:.1f}% |")

        lines.append("\n## Average Confidence by Prompt\n")
        prompt_confidences = {}
        for eval_result in results.values():
            for version, result in eval_result.prompt_results.items():
                if version not in prompt_confidences:
                    prompt_confidences[version] = []
                prompt_confidences[version].append(result.confidence)

        lines.append("| Prompt | Avg Confidence | Samples |")
        lines.append("|--------|----------------|---------|")
        for prompt in sorted(prompt_confidences.keys()):
            confs = prompt_confidences[prompt]
            avg = sum(confs) / len(confs)
            lines.append(f"| {prompt.upper()} | {avg:.1f}% | {len(confs)} |")

        return "\n".join(lines)


if __name__ == "__main__":
    test_response = """
    PATTERN_FOUND: CALL_TEST_JE
    OPCODES: E8 25 05 00 00 85 C0 0F 84
    SKIP_OFFSET: +0
    CONFIDENCE: 92

    ```yara
    rule Bypass_Sample
    {
        meta:
            description = "Delay execution bypass"
            confidence = "92"
            cape_options = "bp0=$pattern+0,action0=skip,count=0"
        strings:
            $pattern = { E8 25 05 00 00 85 C0 0F 84 }
        condition:
            $pattern
    }
    ```
    """

    result = ResponseParser.parse_response(test_response, "v7")
    print(f"Pattern: {result.pattern_type}")
    print(f"Opcodes: {result.opcodes}")
    print(f"Confidence: {result.confidence}")
    print(f"Parse success: {result.parse_success}")