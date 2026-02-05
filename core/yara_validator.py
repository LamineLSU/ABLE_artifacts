
import re
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass


@dataclass
class ValidationResult:

    is_valid: bool
    is_bypass_rule: bool
    errors: List[str]
    warnings: List[str]
    sanitized_rule: Optional[str]


class YaraBypassValidator:


    REQUIRED_BYPASS_META = ['cape_options']

    PLACEHOLDER_PATTERNS = [
        r'\[SKIP_OFFSET\]',
        r'\[SKIP_OFFSET1\]',
        r'\[SKIP_OFFSET2\]',
        r'\[SKIP_OFFSET3\]',
        r'\[OFFSET\]',
        r'\[PATTERN_TYPE\s*value\]',
        r'\[CONFIDENCE\s*value\]',
        r'\[OPCODES_GENERIC[^]]*\]',
    ]

    HEX_STRING_PATTERN = r'(\$\w+\s*=\s*)\{\s*([^}]+)\s*\}'

    def __init__(self):
        self.last_result: Optional[ValidationResult] = None

    def validate(self, yara_rule: str, iteration: int = 0) -> ValidationResult:

        errors = []
        warnings = []
        is_bypass_rule = False
        sanitized = yara_rule
        self._current_iteration = iteration

        sanitized, multi_rule_fixed = self._extract_first_rule(sanitized)
        if multi_rule_fixed:
            warnings.append("Extracted first rule from multiple rules in output")

        sanitized, multiline_fixed = self._fix_multiline_hex_patterns(sanitized)
        if multiline_fixed:
            warnings.append("Fixed multiline hex patterns: collapsed to single line")

        sanitized, comment_fixed = self._fix_comment_style(sanitized)
        if comment_fixed:
            warnings.append("Fixed comment style: converted non-YARA comments (-- or #) to //")

        sanitized, wildcard_fixed = self._fix_wildcard_format(sanitized)
        if wildcard_fixed:
            warnings.append("Fixed wildcard format: converted ???+ to ??")

        sanitized, annotations_fixed = self._strip_inline_annotations(sanitized)
        if annotations_fixed:
            warnings.append("Stripped inline annotations from hex patterns")

        sanitized, pattern_name_fixed = self._fix_invalid_pattern_names(sanitized)
        if pattern_name_fixed:
            warnings.append("Removed or fixed invalid pattern names/syntax")

        sanitized, addr_fixed = self._remove_address_annotations(sanitized)
        if addr_fixed:
            warnings.append("Removed address annotations from patterns")

        broken_format_error = self._check_broken_rule_format(sanitized)
        if broken_format_error:
            errors.append(broken_format_error)
            return ValidationResult(
                is_valid=False,
                is_bypass_rule=False,
                errors=errors,
                warnings=warnings,
                sanitized_rule=None
            )

        if not self._has_basic_structure(sanitized):
            errors.append("Missing basic YARA rule structure (rule name, strings, condition)")
            return ValidationResult(
                is_valid=False,
                is_bypass_rule=False,
                errors=errors,
                warnings=warnings,
                sanitized_rule=None
            )

        regex_issues = self._check_regex_patterns(sanitized)
        if regex_issues:
            for issue in regex_issues:
                errors.append(issue)

        sanitized, quoted_fixed = self._fix_quoted_hex_patterns(sanitized)
        if quoted_fixed:
            warnings.append("Fixed quoted hex strings: converted to brace format")

        sanitized, bare_fixed = self._fix_bare_hex_patterns(sanitized)
        if bare_fixed:
            warnings.append("Fixed bare hex patterns: added braces and spacing")

        sanitized, hex_fixed = self._fix_hex_patterns(sanitized)
        if hex_fixed:
            warnings.append(f"Fixed hex patterns: removed 0x prefix")

        if 'cape_options' in yara_rule.lower():
            is_bypass_rule = True

            cape_opts_valid, cape_opts_error = self._validate_cape_options(sanitized)
            if not cape_opts_valid:
                errors.append(f"Invalid cape_options: {cape_opts_error}")
                sanitized, placeholder_fixed = self._fix_placeholders(sanitized)
                if placeholder_fixed:
                    warnings.append("Fixed placeholder values in cape_options")
        else:
            sanitized, was_renamed = self._rename_patterns_for_bypass(sanitized)
            if was_renamed:
                warnings.append("Auto-renamed patterns to $pattern0, $pattern1, $pattern2")

            sanitized, was_injected = self._inject_cape_options(sanitized)
            if was_injected:
                is_bypass_rule = True
                warnings.append("Auto-injected cape_options based on existing patterns")
            else:
                warnings.append("Missing cape_options - this is a detection rule, not a bypass rule")

        placeholders = self._find_placeholders(sanitized)
        if placeholders:
            errors.append(f"Unresolved placeholders: {', '.join(placeholders)}")

        hex_valid, hex_error = self._validate_hex_strings(sanitized)
        if not hex_valid:
            errors.append(f"Invalid hex pattern: {hex_error}")

        cond_valid, cond_error = self._validate_condition(sanitized)
        if not cond_valid:
            errors.append(f"Invalid condition: {cond_error}")
            sanitized, cond_fixed = self._fix_condition(sanitized)
            if cond_fixed:
                warnings.append("Fixed condition syntax")

        generic_issues = self.get_generic_pattern_issues(sanitized)
        if generic_issues:
            for issue in generic_issues:
                issue_lower = issue.lower()
                is_risky_issue = ("risky" in issue_lower or "too generic" in issue_lower or
                                  "may trigger" in issue_lower or "context bytes" in issue_lower)
                if iteration >= 1 and is_risky_issue:
                    pass
                else:
                    errors.append(f"Generic pattern: {issue}")

        empty_issues = self._check_empty_patterns(sanitized)
        if empty_issues:
            for issue in empty_issues:
                errors.append(f"Empty pattern: {issue}")

        duplicate_issues = self._check_duplicate_patterns(sanitized)
        if duplicate_issues:
            for issue in duplicate_issues:
                errors.append(f"Duplicate pattern: {issue}")

        is_valid = len(errors) == 0

        result = ValidationResult(
            is_valid=is_valid,
            is_bypass_rule=is_bypass_rule,
            errors=errors,
            warnings=warnings,
            sanitized_rule=sanitized if is_valid or sanitized != yara_rule else None
        )

        self.last_result = result
        return result

    def _has_basic_structure(self, rule: str) -> bool:

        has_rule = re.search(r'rule\s+\w+', rule) is not None
        has_strings = 'strings:' in rule.lower()
        has_condition = 'condition:' in rule.lower()
        return has_rule and has_strings and has_condition

    def _check_broken_rule_format(self, rule: str) -> Optional[str]:

        if '=>' in rule:
            return "Rule uses '=>' arrow syntax which is not valid YARA (use $pattern = { hex_bytes } format)"

        if re.search(r'hex\s*\(', rule):
            return "Rule uses 'hex()' function syntax which is not valid YARA (use $pattern = { hex_bytes } format)"

        if re.search(r'pattern\s+["\'][^"\']+["\']', rule):
            return "Rule uses 'pattern \"name\"' syntax which is not valid YARA (use $pattern_name = { hex_bytes } format)"

        strings_match = re.search(r'strings:\s*([\s\S]*?)(?:condition:|$)', rule, re.IGNORECASE)
        if strings_match:
            strings_section = strings_match.group(1)
            if '|' in strings_section and 'condition' not in strings_section.lower():
                return "Rule uses '|' (OR) operator in strings section which is not valid (OR logic belongs in condition section)"

        return None

    def _extract_first_rule(self, rule_text: str) -> Tuple[str, bool]:

        rule_starts = list(re.finditer(r'\brule\s+\w+', rule_text))

        if len(rule_starts) <= 1:
            return rule_text, False

        first_start = rule_starts[0].start()
        second_start = rule_starts[1].start()

        first_rule = rule_text[first_start:second_start]

        brace_count = 0
        end_pos = 0
        for i, char in enumerate(first_rule):
            if char == '{':
                brace_count += 1
            elif char == '}':
                brace_count -= 1
                if brace_count == 0:
                    end_pos = i + 1
                    break

        if end_pos > 0:
            return first_rule[:end_pos], True

        return first_rule.rstrip(), True

    def _fix_multiline_hex_patterns(self, rule: str) -> Tuple[str, bool]:

        fixed = False

        def collapse_pattern(match):
            nonlocal fixed
            prefix = match.group(1)
            content = match.group(2)
            content = ' '.join(content.split())
            if '\n' in match.group(0):
                fixed = True
            return f"{prefix} {content} }}"

        pattern = r'(\$\w+\s*=\s*\{)([\s\S]*?)\}'
        result = re.sub(pattern, collapse_pattern, rule)

        return result, fixed

    def _fix_comment_style(self, rule: str) -> Tuple[str, bool]:

        fixed = False
        lines = rule.split('\n')
        new_lines = []

        for line in lines:
            original_line = line

            if '  --' in line or '\t--' in line or '}  --' in line or '} --' in line:
                line = re.sub(r'(\})(\s*)--(\s*)', r'\1\2//\3', line)
                line = re.sub(r'(\s)--(\s)', r'\1//\2', line)

            if '}' in line and '#' in line:
                last_brace = line.rfind('}')
                hash_after_brace = line.find('#', last_brace)
                if hash_after_brace > last_brace:
                    line = line[:hash_after_brace] + '//' + line[hash_after_brace + 1:]
            elif '#' in line and '{' not in line:
                if re.search(r'\$\w+\s*=.*#', line):
                    line = re.sub(r'(\s)#(\s*\w)', r'\1//\2', line)

            if line != original_line:
                fixed = True
            new_lines.append(line)

        return '\n'.join(new_lines), fixed

    def _fix_wildcard_format(self, rule: str) -> Tuple[str, bool]:

        fixed = False

        def fix_wildcards(match):
            nonlocal fixed
            prefix = match.group(1)
            content = match.group(2)
            original = content

            content = re.sub(r'\?{3,}', '??', content)

            content = re.sub(r'(\?\?)+', lambda m: ' '.join(['??'] * (len(m.group(0)) // 2)), content)

            content = re.sub(r'\s+', ' ', content)

            if content != original:
                fixed = True
            return prefix + '{' + content + '}'

        result = re.sub(r'(=\s*)\{([^}]+)\}', fix_wildcards, rule)

        return result, fixed

    def _strip_inline_annotations(self, rule: str) -> Tuple[str, bool]:

        fixed = False

        def strip_annotations(match):
            nonlocal fixed
            prefix = match.group(1)
            content = match.group(2)
            original = content

            content = re.sub(r'\([^)]*\)', '', content)

            annotation_phrases = [
                r'\bfor\s+the\s+target\s+address\b',
                r'\bfor\s+offset\b',
                r'\bfollowed\s+by\b',
                r'\btarget\s+address\b',
                r'\boffset\b(?!\s*[0-9A-Fa-f])',
                r'\baddress\b',
                r'\binstruction\b',
                r'\bbyte[s]?\b',
                r'\bwildcard[s]?\b',
            ]
            for phrase in annotation_phrases:
                content = re.sub(phrase, '', content, flags=re.IGNORECASE)

            content = re.sub(r',', ' ', content)

            content = re.sub(r'[^0-9A-Fa-f\?\s]', ' ', content)

            content = re.sub(r'\s+', ' ', content).strip()

            tokens = content.split()
            valid_tokens = []
            i = 0
            while i < len(tokens):
                token = tokens[i]
                if token == '??':
                    valid_tokens.append(token)
                    i += 1
                elif len(token) == 2 and re.match(r'^[0-9A-Fa-f]{2}$', token):
                    valid_tokens.append(token.upper())
                    i += 1
                elif len(token) == 1 and re.match(r'^[0-9A-Fa-f]$', token):
                    if i + 1 < len(tokens) and len(tokens[i+1]) == 1 and re.match(r'^[0-9A-Fa-f]$', tokens[i+1]):
                        valid_tokens.append((token + tokens[i+1]).upper())
                        i += 2
                    else:
                        i += 1
                elif len(token) > 2 and re.match(r'^[0-9A-Fa-f]+$', token):
                    for j in range(0, len(token) - 1, 2):
                        valid_tokens.append(token[j:j+2].upper())
                    i += 1
                else:
                    i += 1

            content = ' '.join(valid_tokens)

            if content != original.strip():
                fixed = True

            return prefix + '{ ' + content + ' }'

        result = re.sub(r'(=\s*)\{([^}]+)\}', strip_annotations, rule)

        return result, fixed

    def _fix_invalid_pattern_names(self, rule: str) -> Tuple[str, bool]:

        fixed = False
        lines = rule.split('\n')
        new_lines = []
        in_strings = False
        pattern_counter = 1

        for line in lines:
            stripped = line.strip().lower()

            if 'strings:' in stripped:
                in_strings = True
                new_lines.append(line)
                continue
            elif 'condition:' in stripped or 'meta:' in stripped:
                in_strings = False
                new_lines.append(line)
                continue

            if in_strings and '=' in line and '{' in line:

                if re.match(r'\s*\?+\s*=', line) or re.match(r'\s*\$\?+\s*=', line):
                    hex_match = re.search(r'\{\s*([^}]*)\s*\}', line)
                    if hex_match:
                        hex_content = hex_match.group(1)
                        if re.search(r'\[.*bytes.*\]', hex_content, re.IGNORECASE):
                            fixed = True
                            continue
                        if re.match(r'^[\s\dA-Fa-f\?\s]+$', hex_content.replace(' ', '')):
                            new_name = f'$pattern{pattern_counter}'
                            pattern_counter += 1
                            new_line = re.sub(r'^\s*\$?\?+\s*=', f'        {new_name} =', line)
                            new_lines.append(new_line)
                            fixed = True
                            continue
                    fixed = True
                    continue

                if re.match(r'\s*\[[^\]]+\]\s*=', line):
                    fixed = True
                    continue

                hex_match = re.search(r'\{\s*([^}]*)\s*\}', line)
                if hex_match:
                    hex_content = hex_match.group(1)
                    if re.search(r'\[.*bytes.*\]', hex_content, re.IGNORECASE):
                        fixed = True
                        continue

            new_lines.append(line)

        return '\n'.join(new_lines), fixed

    def _fix_cape_options_placement(self, rule: str) -> Tuple[str, bool]:

        fixed = False

        meta_match = re.search(r'meta:\s*\n([\s\S]*?)(?=strings:|condition:|\})', rule, re.IGNORECASE)
        if meta_match:
            meta_content = meta_match.group(1)
            if 'cape_options' in meta_content.lower():
                return rule, False

        cape_match = re.search(r'cape_options\s*=\s*["\']([^"\']+)["\']', rule)
        if not cape_match:
            return rule, False

        cape_value = cape_match.group(1)

        lines = rule.split('\n')
        new_lines = []
        in_condition = False
        in_meta = False

        for line in lines:
            stripped = line.strip().lower()
            if 'meta:' in stripped:
                in_meta = True
                in_condition = False
            elif 'strings:' in stripped:
                in_meta = False
                in_condition = False
            elif 'condition:' in stripped:
                in_meta = False
                in_condition = True

            if 'cape_options' in line.lower() and not in_meta:
                fixed = True
                continue

            new_lines.append(line)

        if not fixed:
            return rule, False

        result_lines = []
        meta_found = False

        for i, line in enumerate(new_lines):
            result_lines.append(line)
            stripped = line.strip().lower()

            if 'meta:' in stripped and not meta_found:
                meta_found = True
                indent = '        '
                if i + 1 < len(new_lines):
                    next_line = new_lines[i + 1]
                    indent_match = re.match(r'^(\s+)', next_line)
                    if indent_match:
                        indent = indent_match.group(1)
                result_lines.append(f'{indent}cape_options = "{cape_value}"')

        return '\n'.join(result_lines), fixed

    def _remove_address_annotations(self, rule: str) -> Tuple[str, bool]:

        fixed = False
        original = rule

        rule = re.sub(r'\s*at\s*\(0x[0-9A-Fa-f]+\)', '', rule)

        rule = re.sub(r'\s*@\s*0x[0-9A-Fa-f]+', '', rule)

        rule = re.sub(r'\s*\(0x[0-9A-Fa-f]+\)', '', rule)

        rule = re.sub(r'//\s*at\s+address\s+0x[0-9A-Fa-f]+', '', rule)

        rule = re.sub(r'//\s*address:\s*0x[0-9A-Fa-f]+', '', rule)

        if rule != original:
            fixed = True

        return rule, fixed

    def _check_regex_patterns(self, rule: str) -> List[str]:

        issues = []
        regex_patterns = re.findall(r'(\$\w+)\s*=\s*/([^/]+)/', rule)

        for var_name, pattern_content in regex_patterns:
            issues.append(
                f"{var_name}: Regex pattern '/{pattern_content}/' is not valid for bypass rules. "
                f"Use hex byte patterns like {{ E8 ?? ?? ?? ?? }} instead"
            )

        return issues

    def _fix_quoted_hex_patterns(self, rule: str) -> Tuple[str, bool]:

        fixed = False

        def fix_quoted(match):
            nonlocal fixed
            var_part = match.group(1)
            content = match.group(2)

            if re.search(r'[0-9A-Fa-f]{2}', content) or '??' in content:
                fixed_content = self._fix_hex_spacing(content)
                fixed = True
                return f'{var_part}{{ {fixed_content} }}'
            else:
                return match.group(0)

        new_rule = re.sub(r'(\$\w+\s*=\s*)"([^"]+)"', fix_quoted, rule)
        return new_rule, fixed

    def _fix_bare_hex_patterns(self, rule: str) -> Tuple[str, bool]:

        fixed = False

        lines = rule.split('\n')
        new_lines = []

        for line in lines:
            match = re.match(r'^(\s*\$\w+\s*=\s*)([^{"{\n][^\n]*)$', line)
            if match:
                var_part = match.group(1)
                content = match.group(2).strip()

                content = re.sub(r'\s*\(.*\)\s*$', '', content)

                if content and re.match(r'^[0-9A-Fa-f?][0-9A-Fa-f?\s]*$', content):
                    fixed_content = self._fix_hex_spacing(content)
                    new_lines.append(f'{var_part}{{ {fixed_content} }}')
                    fixed = True
                else:
                    new_lines.append(line)
            else:
                new_lines.append(line)

        return '\n'.join(new_lines), fixed

    def _fix_hex_patterns(self, rule: str) -> Tuple[str, bool]:

        fixed = False

        def fix_hex(match):
            nonlocal fixed
            var_part = match.group(1)
            content = match.group(2)

            new_content = re.sub(r'0x([0-9A-Fa-f]+)', r'\1', content)

            new_content = re.sub(r'//.*$', '', new_content, flags=re.MULTILINE).strip()

            new_content = self._fix_hex_spacing(new_content)

            if new_content != content:
                fixed = True
            return var_part + '{ ' + new_content + ' }'

        new_rule = re.sub(self.HEX_STRING_PATTERN, fix_hex, rule)
        return new_rule, fixed

    def _fix_hex_spacing(self, hex_content: str) -> str:

        normalized = ' '.join(hex_content.split())

        tokens = normalized.split(' ')

        result_bytes = []
        for token in tokens:
            if not token:
                continue

            if len(token) == 2 or token == '??':
                result_bytes.append(token.upper() if token != '??' else token)
            elif len(token) == 1:
                result_bytes.append(token.upper())
            else:
                i = 0
                while i < len(token):
                    if token[i:i+2] == '??':
                        result_bytes.append('??')
                        i += 2
                    elif i + 1 < len(token) and token[i] == '?':
                        result_bytes.append('?' + token[i+1].upper())
                        i += 2
                    elif i + 1 < len(token) and token[i+1] == '?':
                        result_bytes.append(token[i].upper() + '?')
                        i += 2
                    elif i + 1 < len(token):
                        result_bytes.append(token[i:i+2].upper())
                        i += 2
                    else:
                        result_bytes.append(token[i].upper())
                        i += 1

        return ' '.join(result_bytes)

    def _validate_cape_options(self, rule: str) -> Tuple[bool, Optional[str]]:

        match = re.search(r'cape_options\s*=\s*"([^"]+)"', rule)
        if not match:
            return False, "cape_options not found or malformed"

        opts = match.group(1)

        if 'bp0=' not in opts and 'bp1=' not in opts:
            return False, "Missing breakpoint definition (bp0= or bp1=)"

        if 'action0=' not in opts and 'action1=' not in opts:
            return False, "Missing action definition (action0= or action1=)"

        if '[' in opts and ']' in opts:
            return False, "Contains unresolved placeholder brackets"

        bp_match = re.search(r'bp\d+=\$\w+\+(\d+|0x[0-9A-Fa-f]+)', opts)
        if not bp_match:
            if re.search(r'bp\d+=\$\w+,', opts):
                return False, "Missing offset in breakpoint (should be $pattern+N)"

        return True, None

    def _fix_placeholders(self, rule: str) -> Tuple[str, bool]:

        fixed = False
        new_rule = rule

        for placeholder in ['[SKIP_OFFSET]', '[SKIP_OFFSET1]', '[SKIP_OFFSET2]', '[SKIP_OFFSET3]', '[OFFSET]']:
            if placeholder in new_rule:
                new_rule = new_rule.replace(placeholder, '0')
                fixed = True

        return new_rule, fixed

    def _find_placeholders(self, rule: str) -> List[str]:

        found = []
        for pattern in self.PLACEHOLDER_PATTERNS:
            matches = re.findall(pattern, rule, re.IGNORECASE)
            found.extend(matches)
        return found

    def _validate_hex_strings(self, rule: str) -> Tuple[bool, Optional[str]]:

        hex_patterns = re.findall(r'\$\w+\s*=\s*\{\s*([^}]+)\s*\}', rule)

        for pattern in hex_patterns:
            cleaned = pattern.strip()

            asm_mnemonics_spaced = ['MO V', 'PU SH', 'SU B', 'DW OR', 'PT R', 'PO P', 'EA X', 'EB X', 'ES I', 'ED I']
            for mnemonic in asm_mnemonics_spaced:
                if mnemonic in cleaned:
                    return False, f"Hex pattern contains spaced assembly mnemonic '{mnemonic}' - use hex bytes only, not assembly text"

            asm_instructions = ['PUSH', 'POP', 'MOV', 'CALL', 'RET', 'JMP', 'JZ', 'JNZ', 'JE', 'JNE', 'CMP', 'TEST', 'ADD', 'SUB', 'XOR', 'AND', 'OR', 'LEA', 'NOP']
            for instr in asm_instructions:
                if re.search(r'\b' + instr + r'\b', cleaned):
                    return False, f"Hex pattern contains assembly instruction '{instr}' - use hex bytes only (e.g., 'E8' for CALL)"

            registers = ['EAX', 'EBX', 'ECX', 'EDX', 'ESI', 'EDI', 'EBP', 'ESP']
            for reg in registers:
                if re.search(r'\b' + reg + r'\b', cleaned):
                    return False, f"Hex pattern contains register name '{reg}' - use hex bytes only"

            if ':' in cleaned:
                return False, "Hex pattern contains ':' which is not valid hex (use space-separated hex bytes only)"

            if re.search(r'\?{3,}', cleaned):
                return False, "Hex pattern contains multiple consecutive '?' - use '?? ??' with spaces between wildcard bytes"

            if '/' in cleaned:
                return False, "Hex pattern contains '/' which is not valid hex (use separate patterns or ?? wildcards)"

            if re.search(r'0x[0-9A-Fa-f]+:', cleaned):
                return False, "Hex pattern contains address prefix (0x....:) - remove the address prefix"

            if re.search(r'[0-9A-Fa-f]{6,}h?\b', cleaned):
                return False, "Hex pattern contains long hex string without spaces - separate into 2-char bytes (e.g., 'E8 74 FA FF FF' not 'E874FAFFFF')"

            if not re.match(r'^[\s0-9A-Fa-f\?]+$', cleaned):
                if '0x' in cleaned:
                    return False, "Hex pattern contains '0x' prefix (should be bare hex)"
                if '//' in cleaned:
                    return False, "Hex pattern contains comment (move comments outside braces)"
                if '.' in cleaned:
                    return False, "Hex pattern contains '.' which is not valid hex (only 0-9, A-F, and ?? wildcards allowed)"
                if '>' in cleaned:
                    return False, "Hex pattern contains '>' which is not valid hex (only 0-9, A-F, and ?? wildcards allowed)"
                if '<' in cleaned:
                    return False, "Hex pattern contains '<' which is not valid hex (only 0-9, A-F, and ?? wildcards allowed)"
                if '[' in cleaned or ']' in cleaned:
                    return False, "Hex pattern contains '[' or ']' which is not valid inside {} (use only hex bytes like 'E8 ?? ?? ?? ??')"
                if ',' in cleaned:
                    return False, "Hex pattern contains ',' which is not valid inside {} (hex bytes should be space-separated)"
                if 'bytes' in cleaned.lower():
                    return False, "Hex pattern contains placeholder text like '[6-20 bytes]' - replace with actual hex bytes"
                if 'wildcard' in cleaned.lower():
                    return False, "Hex pattern contains placeholder text like 'wildcard' - use ?? for wildcards"
                if '(' in cleaned or ')' in cleaned:
                    return False, "Hex pattern contains parentheses which is not valid hex"
                if '#' in cleaned:
                    return False, "Hex pattern contains '#' comment marker - move comments outside braces"
                return False, f"Invalid characters in hex pattern: {cleaned[:50]}"

            hex_bytes = cleaned.split()
            if len(hex_bytes) == 0:
                return False, "Empty hex pattern"

            for byte in hex_bytes:
                if byte != '??' and len(byte) != 2:
                    if len(byte) == 1:
                        return False, f"Single character '{byte}' - hex bytes must be 2 chars (e.g., '0A' not 'A')"
                    return False, f"Invalid hex byte '{byte}' - must be exactly 2 hex chars or ?? (e.g., 'E8', 'FF', '??')"

        return True, None

    def _validate_condition(self, rule: str) -> Tuple[bool, Optional[str]]:

        match = re.search(r'condition:\s*(.+?)(?:\n\s*\}|$)', rule, re.DOTALL)
        if not match:
            return False, "Could not extract condition"

        condition = match.group(1).strip()

        if 'all of:' in condition:
            return False, "'all of:' should be 'all of them' or 'all of ($pattern*)'"

        if 'any of:' in condition:
            return False, "'any of:' should be 'any of them' or 'any of ($pattern*)'"

        return True, None

    def _fix_condition(self, rule: str) -> Tuple[str, bool]:

        fixed = False
        new_rule = rule

        if 'all of:' in new_rule:
            new_rule = re.sub(
                r'condition:\s*all of:\s*(\$\w+)\s*(\$\w+)',
                r'condition:\n        all of them',
                new_rule
            )
            fixed = True

        return new_rule, fixed

    def _extract_pattern_names(self, rule: str) -> List[str]:

        patterns = re.findall(r'(\$\w+)\s*=\s*\{[^}]*\}', rule)
        return patterns

    def _inject_cape_options(self, rule: str) -> Tuple[str, bool]:

        if 'cape_options' in rule.lower():
            return rule, False

        pattern_names = self._extract_pattern_names(rule)
        if not pattern_names:
            return rule, False

        cape_parts = []
        for i, pname in enumerate(pattern_names[:3]):
            cape_parts.append(f"bp{i}={pname}+0,action{i}=skip")

        cape_options = ','.join(cape_parts) + ",count=0"

        if 'meta:' in rule.lower():
            meta_match = re.search(r'(meta:\s*\n\s*\w+\s*=\s*[^\n]+)', rule, re.IGNORECASE)
            if meta_match:
                insertion_point = meta_match.end()
                new_rule = (
                    rule[:insertion_point] +
                    f'\n        cape_options = "{cape_options}"' +
                    rule[insertion_point:]
                )
                return new_rule, True
        else:
            rule_match = re.search(r'(rule\s+\w+\s*\{)', rule)
            if rule_match:
                insertion_point = rule_match.end()
                new_rule = (
                    rule[:insertion_point] +
                    f'\n    meta:\n        description = "Auto-generated bypass rule"\n        cape_options = "{cape_options}"\n' +
                    rule[insertion_point:]
                )
                return new_rule, True

        return rule, False

    def _rename_patterns_for_bypass(self, rule: str) -> Tuple[str, bool]:

        pattern_names = self._extract_pattern_names(rule)
        if not pattern_names:
            return rule, False

        standard_names = {'$pattern0', '$pattern1', '$pattern2'}
        if all(p in standard_names for p in pattern_names[:3]):
            return rule, False

        new_rule = rule
        renamed = False
        for i, old_name in enumerate(pattern_names[:3]):
            new_name = f'$pattern{i}'
            if old_name != new_name:
                new_rule = re.sub(
                    r'\b' + re.escape(old_name) + r'\b',
                    new_name,
                    new_rule
                )
                renamed = True

        return new_rule, renamed

    MIN_PATTERN_LENGTH = 6

    OVERLY_GENERIC_PATTERNS = [
        ['74', '??'],
        ['75', '??'],
        ['EB', '??'],
    ]

    RISKY_ALONE_PATTERNS = [
        ['FF', '15', '??', '??', '??', '??'],
        ['E8', '??', '??', '??', '??'],
        ['FF', '25', '??', '??', '??', '??'],
    ]

    MIN_CONTEXT_FOR_RISKY = 4

    MIN_CONTEXT_BYTES = 0

    MIN_PATTERNS_FOR_GENERIC = 1

    def _check_risky_pattern(self, var_name: str, bytes_list: List[str]) -> Optional[str]:

        for risky_pattern in self.RISKY_ALONE_PATTERNS:
            risky_len = len(risky_pattern)

            if len(bytes_list) == risky_len:
                if all(b1 == b2 or b2 == '??' for b1, b2 in zip(bytes_list, risky_pattern)):
                    pattern_str = ' '.join(risky_pattern)
                    return (
                        f"{var_name}: Pattern {{ {pattern_str} }} alone is too generic and may trigger "
                        f"new signatures. Add {self.MIN_CONTEXT_FOR_RISKY}+ context bytes (e.g., TEST/CMP/JZ after the CALL)"
                    )

            if len(bytes_list) >= risky_len:
                if all(b1 == b2 or b2 == '??' for b1, b2 in zip(bytes_list[:risky_len], risky_pattern)):
                    context_after = len(bytes_list) - risky_len
                    if context_after < self.MIN_CONTEXT_FOR_RISKY:
                        pattern_str = ' '.join(risky_pattern)
                        return (
                            f"{var_name}: Pattern starts with {{ {pattern_str} }} but only has "
                            f"{context_after} context bytes after. Need {self.MIN_CONTEXT_FOR_RISKY}+ bytes "
                            f"to avoid triggering new signatures"
                        )

        return None

    def _is_exact_generic_pattern(self, bytes_list: List[str]) -> bool:

        bytes_upper = [b.upper() for b in bytes_list]

        for generic_pattern in self.OVERLY_GENERIC_PATTERNS:
            if len(bytes_upper) == len(generic_pattern):
                if all(b1 == b2 or b2 == '??' for b1, b2 in zip(bytes_upper, generic_pattern)):
                    return True
        return False

    def _contains_generic_pattern_with_context(self, bytes_list: List[str]) -> Tuple[bool, bool]:

        bytes_upper = [b.upper() for b in bytes_list]

        for generic_pattern in self.OVERLY_GENERIC_PATTERNS:
            gen_len = len(generic_pattern)

            for i in range(len(bytes_upper) - gen_len + 1):
                segment = bytes_upper[i:i + gen_len]

                if all(b1 == b2 or b2 == '??' for b1, b2 in zip(segment, generic_pattern)):
                    context_before = i
                    context_after = len(bytes_upper) - (i + gen_len)

                    total_context = context_before + context_after
                    if total_context >= self.MIN_CONTEXT_BYTES:
                        return True, True
                    else:
                        return True, False

        return False, True

    def _is_too_generic(self, rule: str) -> bool:

        hex_patterns = re.findall(r'\$\w+\s*=\s*\{\s*([^}]+)\s*\}', rule)

        if not hex_patterns:
            return True

        total_patterns = len(hex_patterns)
        generic_without_context = []
        patterns_with_context = []

        for pattern in hex_patterns:
            bytes_list = [b.upper() for b in pattern.strip().split()]

            if len(bytes_list) < self.MIN_PATTERN_LENGTH:
                return True

            if all(b == '??' for b in bytes_list):
                return True

            wildcard_count = sum(1 for b in bytes_list if b == '??')
            if wildcard_count / len(bytes_list) > 0.8:
                return True

            contains_generic, has_context = self._contains_generic_pattern_with_context(bytes_list)

            if contains_generic:
                if has_context:
                    patterns_with_context.append(pattern)
                else:
                    generic_without_context.append(pattern)
            else:
                patterns_with_context.append(pattern)

        if generic_without_context:
            if total_patterns >= self.MIN_PATTERNS_FOR_GENERIC and len(patterns_with_context) >= 2:
                return False
            else:
                return True

        return False

    def get_generic_pattern_issues(self, rule: str) -> List[str]:

        issues = []
        hex_patterns = re.findall(r'(\$\w+)\s*=\s*\{\s*([^}]+)\s*\}', rule)

        total_patterns = len(hex_patterns)
        generic_without_context = []
        patterns_with_context = []

        for var_name, pattern in hex_patterns:
            bytes_list = [b.upper() for b in pattern.strip().split()]

            if len(bytes_list) < self.MIN_PATTERN_LENGTH:
                issues.append(f"{var_name}: Pattern too short ({len(bytes_list)} bytes, need at least {self.MIN_PATTERN_LENGTH})")
                continue

            risky_issue = self._check_risky_pattern(var_name, bytes_list)
            if risky_issue:
                issues.append(risky_issue)

            contains_generic, has_context = self._contains_generic_pattern_with_context(bytes_list)

            if contains_generic:
                if has_context:
                    patterns_with_context.append(var_name)
                else:
                    generic_without_context.append((var_name, bytes_list))
            else:
                patterns_with_context.append(var_name)

        if generic_without_context:
            if total_patterns >= self.MIN_PATTERNS_FOR_GENERIC and len(patterns_with_context) >= 2:
                pass
            else:
                for var_name, bytes_list in generic_without_context:
                    for generic_pattern in self.OVERLY_GENERIC_PATTERNS:
                        gen_len = len(generic_pattern)
                        for i in range(len(bytes_list) - gen_len + 1):
                            segment = bytes_list[i:i + gen_len]
                            if all(b1 == b2 or b2 == '??' for b1, b2 in zip(segment, generic_pattern)):
                                pattern_str = ' '.join(generic_pattern)
                                issues.append(
                                    f"{var_name}: Contains generic pattern {{ {pattern_str} }} - "
                                    f"add {self.MIN_CONTEXT_BYTES}+ bytes context OR use {self.MIN_PATTERNS_FOR_GENERIC}+ patterns with 2+ having context"
                                )
                                break
                        else:
                            continue
                        break

        return issues

    def _check_empty_patterns(self, rule: str) -> List[str]:

        issues = []
        empty_patterns = re.findall(r'(\$\w+)\s*=\s*\{\s*\}', rule)
        for var_name in empty_patterns:
            issues.append(f"{var_name} is empty - must contain byte patterns")

        whitespace_patterns = re.findall(r'(\$\w+)\s*=\s*\{\s+\}', rule)
        for var_name in whitespace_patterns:
            if var_name not in empty_patterns:
                issues.append(f"{var_name} is empty - must contain byte patterns")

        return issues

    def _check_duplicate_patterns(self, rule: str) -> List[str]:

        issues = []
        patterns = re.findall(r'(\$\w+)\s*=\s*\{\s*([^}]*)\s*\}', rule)

        if len(patterns) < 2:
            return issues

        normalized = {}
        for var_name, pattern in patterns:
            if not pattern.strip():
                continue
            norm_pattern = ' '.join(pattern.upper().split())
            if norm_pattern not in normalized:
                normalized[norm_pattern] = []
            normalized[norm_pattern].append(var_name)

        for pattern, var_names in normalized.items():
            if len(var_names) > 1:
                issues.append(
                    f"{', '.join(var_names)} are identical - each pattern must target a different evasion point"
                )

        return issues

    def validate_and_fix(self, yara_rule: str, iteration: int = 0) -> Tuple[bool, str, List[str]]:

        result = self.validate(yara_rule, iteration=iteration)

        issues = result.errors + [f"Warning: {w}" for w in result.warnings]

        if result.sanitized_rule:
            return result.is_valid, result.sanitized_rule, issues
        else:
            return result.is_valid, yara_rule, issues

    def is_valid_bypass_rule(self, yara_rule: str) -> bool:

        result = self.validate(yara_rule)
        return result.is_valid and result.is_bypass_rule


def validate_yara_rule(yara_rule: str, iteration: int = 0) -> ValidationResult:

    validator = YaraBypassValidator()
    return validator.validate(yara_rule, iteration=iteration)


def sanitize_yara_rule(yara_rule: str, iteration: int = 0) -> Tuple[bool, str, List[str]]:

    validator = YaraBypassValidator()
    return validator.validate_and_fix(yara_rule, iteration=iteration)


if __name__ == "__main__":
    test_rule_1 = '''
rule CustomCodePattern
{
    meta:
        description = "Test rule"

    strings:
        $add_seq = { 0x03 C3 0x03 C1 }

    condition:
        $add_seq
}
'''

    test_rule_2 = '''
rule Bypass_Sample_Evolved
{
    meta:
        description = "Test bypass"
        cape_options = "bp0=$pattern+[SKIP_OFFSET],action0=skip,count=0"

    strings:
        $pattern = { FF 15 ?? ?? ?? ?? }

    condition:
        $pattern
}
'''

    test_rule_3 = '''
rule Bypass_Sample
{
    meta:
        description = "Valid bypass rule"
        cape_options = "bp0=$pattern+0,action0=skip,count=0"

    strings:
        $pattern = { E8 ?? ?? ?? ?? 85 C0 74 ?? }

    condition:
        $pattern
}
'''

    test_rule_4 = '''
rule TestRule
{
    meta:
        description = "Test"

    strings:
        $a = { 8B 16 50 51 }
        $b = { 5E 5D C3 }

    condition:
        all of:
            $a
            $b
}
'''

    test_rule_5 = '''
rule MaliciousPattern
{
    meta:
        description = "Test regex pattern"
        cape_options = "bp0=$c+0,action0=skip,count=0"

    strings:
        $a = /call edx/
        $b = /call 0x418DB0/
        $c = { 83 C4 04 }

    condition:
        all of ($a, $b, $c)
}
'''

    test_rule_6 = '''
rule ExitFunctionSignatures
{
    meta:
        description = "Test quoted hex"

    strings:
        $pattern0 = "FF7508 E8 ?? ?? ?? ??"
        $pattern1 = "FF15 ?? ?? ?? ??"
        $pattern2 = "55 8BEC FF7508 E8 ?? ?? ?? ??"

    condition:
        any of them
}
'''

    test_rule_7 = '''
rule EvasionCheck {
    meta:
        description = "Test bare hex"
    strings:
        $a = E8?? ?? ?? ?? 83F801 7420
        $b = A801 7510
        $c = FF1514613A00
    condition:
        all of them
}
'''

    test_rule_8 = '''
rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,count=0"

    strings:
        $pattern0 = { E8 55 ?? ?? ?? ?? }
        $pattern1 = { 74 3F ??
                     74 3F ??
                     74 3F ?? }

    condition:
        any of them
}
'''

    test_rule_9 = '''
rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,count=0"

    strings:
        $pattern0 = { [6-20 bytes with wildcards] }
        $pattern1 = { [6-20 bytes - DIFFERENT sequence] }

    condition:
        any of them
}
'''

    test_rule_10 = '''
rule Bypass_Evasion_Patterns {
    meta:
        description = "Bypass evasion detection"
        cape_options = "bp0=$pattern0+0,action0=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? E8 ?? }
        $pattern1 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? ?? .? ?. ?? .? ?. ?? .? ?. }
        $pattern2 = { FC F8 ?? > ?? ?? ?? ?? ?? > ?? ?? }

    condition:
        any of them
}
'''

    test_rule_11 = '''
rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,count=0"

    strings:
        $pattern0 = { [4 1B 8D 1, 41 B8 DB ] }
        $pattern1 = { [4 1B 8E C, 41 B8 EE ] }

    condition:
        any of them
}
'''

    test_rule_12 = '''
rule Bypass_Evasion {
    // Rule 0: Bypass after the first function call (E825050000)
    pattern "0" => hex("E825050000", [wildcard] "??" ),

    // Rule 1: Bypass before another function call
    pattern "1" => hex("85C0", [wildcard] "??") | hex("0F8433FDFFFF", wildcard),

    // Rule 2: Bypass at the end of a sequence (E9B5FCFFFF)
    pattern "2" => hex("01D6"),
}
'''

    test_rule_13 = '''
rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 1A ???? ???? 8B 45 }
        $pattern1 = { E8 FFFFFF 83 C4 ?????? 6A }

    condition:
        any of them
}
'''

    test_rule_14 = '''
rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74/75 1A 8B 45 E8 }

    condition:
        any of them
}
'''

    test_rule_15 = '''
rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,count=0"

    strings:
        $pattern0 = { 0x0040E7F6: E8 ?? ?? ?? ?? 85 C0 }

    condition:
        any of them
}
'''

    test_rule_16 = '''
rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }
        $pattern1 = { E8 ?? ?? ?? ?? 73 4A ??:?? ?? ??:? 62 ??:? ?? ?? ?? }

    condition:
        any of them
}
'''

    test_rule_17 = '''
rule BypassSample
{
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = {83 F8 01 (cmp), 74 20 (je 0041B930h), ?? for the target address}
        $pattern1 = {E8 ?? (call dword ptr [0042F13Ch]), 6A ??, 5A ??, 8B CE E8 ?? followed by ?? for offset}
        $pattern2 = {74 ?? (je 0041B930h), 83 F8 01 (cmp), ?? for target address}

    condition:
        any of them
}
'''

    validator = YaraBypassValidator()

    all_tests = [
        (test_rule_1, "0x prefix"),
        (test_rule_2, "placeholder"),
        (test_rule_3, "valid bypass"),
        (test_rule_4, "bad condition"),
        (test_rule_5, "regex patterns"),
        (test_rule_6, "quoted hex strings"),
        (test_rule_7, "bare hex without braces"),
        (test_rule_8, "multiline hex pattern"),
        (test_rule_9, "invalid placeholder text in hex"),
        (test_rule_10, "invalid characters (. and >) in hex"),
        (test_rule_11, "brackets and comma inside hex"),
        (test_rule_12, "completely broken rule format"),
        (test_rule_13, "multiple consecutive question marks"),
        (test_rule_14, "slash in hex patterns"),
        (test_rule_15, "address prefix in hex patterns"),
        (test_rule_16, "colon syntax in patterns"),
        (test_rule_17, "inline annotations in hex patterns"),
    ]

    for i, (rule, desc) in enumerate(all_tests, 1):
        print(f"\n{'='*60}")
        print(f"Test Case {i}: {desc}")
        print('='*60)

        result = validator.validate(rule)

        print(f"Valid: {result.is_valid}")
        print(f"Is Bypass Rule: {result.is_bypass_rule}")

        if result.errors:
            print(f"Errors:")
            for e in result.errors:
                print(f"  - {e}")

        if result.warnings:
            print(f"Warnings:")
            for w in result.warnings:
                print(f"  - {w}")

        if result.sanitized_rule and result.sanitized_rule != rule:
            print(f"\nSanitized Rule:")
            print(result.sanitized_rule)
