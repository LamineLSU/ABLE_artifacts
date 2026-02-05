
import re
import yaml
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass


@dataclass
class PromptMetadata:

    version: str
    name: str
    accuracy: float
    validation_samples: int
    speed: str
    use_case: str
    description: str
    recommended: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            'version': self.version,
            'name': self.name,
            'accuracy': self.accuracy,
            'validation_samples': self.validation_samples,
            'speed': self.speed,
            'use_case': self.use_case,
            'description': self.description,
            'recommended': self.recommended
        }


class PromptLoader:


    DEFAULT_PROMPTS_DIR = Path(__file__).parent

    FRONTMATTER_PATTERN = re.compile(
        r'^---\s*\n(.*?)\n---\s*\n(.*)$',
        re.DOTALL
    )

    def __init__(self, prompts_dir: Optional[Union[str, Path]] = None):

        self.prompts_dir = Path(prompts_dir) if prompts_dir else self.DEFAULT_PROMPTS_DIR

        self._prompt_cache: Dict[str, str] = {}
        self._metadata_cache: Dict[str, PromptMetadata] = {}

        self._discover_prompts()

    def _discover_prompts(self) -> None:

        self._prompt_files: Dict[str, Path] = {}

        for md_file in self.prompts_dir.glob("v*.md"):
            version = md_file.stem.split('_')[0].lower()
            self._prompt_files[version] = md_file

        retry_file = self.prompts_dir / "retry_feedback.md"
        if retry_file.exists():
            self._prompt_files["retry"] = retry_file

    def _load_prompt_file(self, version: str) -> tuple[str, PromptMetadata]:

        if version not in self._prompt_files:
            raise ValueError(
                f"Unknown prompt version: {version}. "
                f"Available: {list(self._prompt_files.keys())}"
            )

        file_path = self._prompt_files[version]
        content = file_path.read_text(encoding='utf-8')

        match = self.FRONTMATTER_PATTERN.match(content)
        if match:
            frontmatter_yaml = match.group(1)
            prompt_content = match.group(2).strip()

            try:
                metadata_dict = yaml.safe_load(frontmatter_yaml)
            except yaml.YAMLError as e:
                raise ValueError(f"Invalid YAML frontmatter in {file_path}: {e}")
        else:
            prompt_content = content.strip()
            metadata_dict = {
                'version': version,
                'name': f'Prompt {version}',
                'accuracy': 0.0,
                'validation_samples': 0,
                'speed': 'unknown',
                'use_case': 'Unknown',
                'description': 'No description'
            }

        metadata = PromptMetadata(
            version=metadata_dict.get('version', version),
            name=metadata_dict.get('name', f'Prompt {version}'),
            accuracy=float(metadata_dict.get('accuracy', 0.0)),
            validation_samples=int(metadata_dict.get('validation_samples', 0)),
            speed=metadata_dict.get('speed', 'unknown'),
            use_case=metadata_dict.get('use_case', 'Unknown'),
            description=metadata_dict.get('description', 'No description'),
            recommended=metadata_dict.get('recommended', False)
        )

        return prompt_content, metadata

    def get_prompt(self, version: str) -> str:

        version = version.lower()

        if version == "recommended":
            version = self.get_recommended_version()

        if version in self._prompt_cache:
            return self._prompt_cache[version]

        prompt_content, metadata = self._load_prompt_file(version)

        self._prompt_cache[version] = prompt_content
        self._metadata_cache[version] = metadata

        return prompt_content

    def get_metadata(self, version: str) -> PromptMetadata:

        version = version.lower()

        if version not in self._metadata_cache:
            self.get_prompt(version)

        return self._metadata_cache[version]

    def format_prompt(self, version: str, **kwargs) -> str:

        template = self.get_prompt(version)

        for key, value in kwargs.items():
            template = template.replace(f'{{{{{key}}}}}', str(value))
            template = template.replace(f'{{{key}}}', str(value))

        return template

    def format_retry_prompt(self, original_version: str, original_trace: str,
                            previous_rule: str, errors: List[str],
                            error_analysis: str = "") -> str:

        original_prompt = self.format_prompt(original_version, trace=original_trace)

        retry_template = self.get_prompt("retry")

        errors_text = "\n".join(f"- {e}" for e in errors) if errors else "- Unknown validation error"

        if not error_analysis:
            error_analysis = self._generate_error_analysis(errors)

        formatted = retry_template
        formatted = formatted.replace("{{errors}}", errors_text)
        formatted = formatted.replace("{{previous_rule}}", previous_rule or "No rule was extracted from the response")
        formatted = formatted.replace("{{error_analysis}}", error_analysis)
        formatted = formatted.replace("{{original_prompt}}", original_prompt)

        return formatted

    def _generate_error_analysis(self, errors: List[str]) -> str:

        analysis = []
        seen_issues = set()

        for error in errors:
            error_lower = error.lower()

            if "too short" in error_lower and "length" not in seen_issues:
                analysis.append("**Pattern Length Issue:** Your patterns are too short. Each pattern must be 10-20 bytes. Combine 2-4 consecutive instructions from the trace into each pattern.")
                seen_issues.add("length")

            elif ("wildcard" in error_lower or "address" in error_lower or "hardcoded" in error_lower) and "wildcard" not in seen_issues:
                analysis.append("**Wildcard Issue:** You have hardcoded address or offset bytes. Replace all memory addresses, CALL/JMP offsets (4 bytes after opcode), and displacement bytes with ?? wildcards.")
                seen_issues.add("wildcard")

            elif ("duplicate" in error_lower or "same" in error_lower or "identical" in error_lower) and "duplicate" not in seen_issues:
                analysis.append("**Duplicate Patterns:** Two or more patterns are identical. Each of the 3 patterns must be a DIFFERENT hex sequence targeting different evasion points.")
                seen_issues.add("duplicate")

            elif ("cape_options" in error_lower or "detection rule" in error_lower or "bypass rule" in error_lower) and "cape" not in seen_issues:
                analysis.append("**⚠️ CRITICAL - Missing cape_options:** Your rule is a detection rule, NOT a bypass rule. You MUST add cape_options in the meta section. Copy this EXACTLY:\n\n`cape_options = \"bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0\"`\n\nThis tells CAPE to set breakpoints on each pattern and skip execution.")
                seen_issues.add("cape")

            elif ("syntax" in error_lower or "parse" in error_lower or "invalid" in error_lower) and "syntax" not in seen_issues:
                analysis.append("**YARA Syntax Error:** The rule has syntax errors. Check: matching braces { }, proper hex format with spaces between bytes, and correct string assignment format `$name = { hex bytes }`")
                seen_issues.add("syntax")

            elif ("pattern" in error_lower and ("3" in error_lower or "count" in error_lower or "only" in error_lower)) and "count" not in seen_issues:
                analysis.append("**⚠️ CRITICAL - Pattern Count Issue:** The rule must have EXACTLY 3 patterns named `$pattern0`, `$pattern1`, `$pattern2`. You currently have the wrong number. Go back to the trace and select 3 DIFFERENT evasion points.")
                seen_issues.add("count")

            elif ("one pattern" in error_lower or "single pattern" in error_lower) and "count" not in seen_issues:
                analysis.append("**⚠️ CRITICAL - Only 1 Pattern Found:** You generated only 1 pattern, but 3 are required. Go back to the trace and identify 3 DIFFERENT bypass points. Name them `$pattern0`, `$pattern1`, `$pattern2`.")
                seen_issues.add("count")

        if not analysis:
            analysis.append("Please review the errors above and ensure your rule follows all requirements: 3 different patterns, 10-20 bytes each, wildcards for addresses, and cape_options in meta.")

        return "\n\n".join(analysis)

    def list_prompts(self) -> List[str]:

        versioned = [v for v in self._prompt_files.keys() if v.startswith('v') and v[1:].split('_')[0].isdigit()]
        return sorted(versioned, key=lambda x: int(x[1:]))

    def get_recommended_version(self) -> str:

        for version in self._prompt_files:
            try:
                meta = self.get_metadata(version)
                if meta.recommended:
                    return version
            except Exception:
                continue

        return "v7"

    def get_all_prompts(self) -> Dict[str, str]:

        return {v: self.get_prompt(v) for v in self.list_prompts()}

    def get_all_metadata(self) -> Dict[str, PromptMetadata]:

        return {v: self.get_metadata(v) for v in self.list_prompts()}

    def get_prompt_summary(self) -> str:

        lines = [
            "Prompt Version Summary",
            "=" * 80,
            f"{'Version':<8} {'Name':<32} {'Accuracy':<10} {'Speed':<8} {'Samples':<8}",
            "-" * 80,
        ]

        recommended = self.get_recommended_version()

        for version in self.list_prompts():
            meta = self.get_metadata(version)
            rec_marker = " [RECOMMENDED]" if version == recommended else ""
            lines.append(
                f"{version:<8} {meta.name:<32} {meta.accuracy*100:>6.0f}%    "
                f"{meta.speed:<8} {meta.validation_samples:<8}{rec_marker}"
            )

        lines.append("-" * 80)
        lines.append(f"Recommended: {recommended}")

        return "\n".join(lines)

    def reload(self) -> None:

        self._prompt_cache.clear()
        self._metadata_cache.clear()
        self._discover_prompts()


_default_loader: Optional[PromptLoader] = None


def get_loader(prompts_dir: Optional[str] = None) -> PromptLoader:

    global _default_loader

    if _default_loader is None or prompts_dir is not None:
        _default_loader = PromptLoader(prompts_dir)

    return _default_loader


def get_prompt(version: str) -> str:

    return get_loader().get_prompt(version)


def format_prompt(version: str, trace: str) -> str:

    return get_loader().format_prompt(version, trace=trace)


def list_prompts() -> List[str]:

    return get_loader().list_prompts()


def get_prompt_metadata(version: str) -> PromptMetadata:

    return get_loader().get_metadata(version)


def get_all_prompts_for_evaluation() -> List[tuple]:

    loader = get_loader()
    return [
        (v, loader.get_prompt(v), loader.get_metadata(v))
        for v in loader.list_prompts()
    ]


def get_prompt_summary() -> str:

    return get_loader().get_prompt_summary()


RECOMMENDED_PROMPT = "v7"


def _init_legacy_constants():

    global RECOMMENDED_PROMPT

    try:
        loader = get_loader()
        RECOMMENDED_PROMPT = loader.get_recommended_version()
    except Exception:
        RECOMMENDED_PROMPT = "v7"


_init_legacy_constants()
