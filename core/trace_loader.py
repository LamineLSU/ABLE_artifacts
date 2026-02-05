
import os
import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass


@dataclass
class TraceInfo:

    trace_id: int
    exit_address: str
    instructions: List[Dict]
    raw_text: str
    instruction_count: int


@dataclass
class SampleTraces:

    sha256: str
    source: str
    report_url: Optional[str]
    timestamp: str
    traces: List[TraceInfo]
    total_traces: int


class TraceLoader:


    def __init__(self, trace_dir: Optional[str] = None):

        if trace_dir:
            self.trace_dir = Path(trace_dir)
        else:
            self.trace_dir = Path(__file__).parent.parent / "binary_trace"

        if not self.trace_dir.exists():
            self.trace_dir.mkdir(parents=True, exist_ok=True)
            print(f"[*] Created trace directory: {self.trace_dir}")

    def list_samples(self) -> List[str]:

        samples = []
        if self.trace_dir.exists():
            for item in self.trace_dir.iterdir():
                if item.is_dir() and len(item.name) == 64:
                    txt_file = item / f"{item.name}_exitprocess_traces.txt"
                    json_file = item / f"{item.name}_exitprocess_traces.json"
                    if txt_file.exists() or json_file.exists():
                        samples.append(item.name)
        return sorted(samples)

    def sample_exists(self, sha256: str) -> bool:

        sample_dir = self.trace_dir / sha256
        if not sample_dir.exists():
            return False
        txt_file = sample_dir / f"{sha256}_exitprocess_traces.txt"
        json_file = sample_dir / f"{sha256}_exitprocess_traces.json"
        return txt_file.exists() or json_file.exists()

    def load_traces(self, sha256: str) -> Optional[SampleTraces]:

        sample_dir = self.trace_dir / sha256
        if not sample_dir.exists():
            print(f"[!] Sample directory not found: {sha256}")
            return None

        json_file = sample_dir / f"{sha256}_exitprocess_traces.json"
        if json_file.exists():
            return self._load_from_json(sha256, json_file)

        txt_file = sample_dir / f"{sha256}_exitprocess_traces.txt"
        if txt_file.exists():
            return self._load_from_txt(sha256, txt_file)

        print(f"[!] No trace files found for: {sha256}")
        return None

    def _load_from_json(self, sha256: str, json_file: Path) -> SampleTraces:

        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)

        traces = []
        for i, trace_data in enumerate(data.get('traces', [])):
            instructions = trace_data.get('instructions', trace_data.get('context_instructions', []))
            exit_addr = trace_data.get('exit_address', trace_data.get('exitprocess_address', ''))

            normalized_instructions = []
            for instr in instructions:
                normalized = {
                    'address': instr.get('address', ''),
                    'opcode': instr.get('opcode', ''),
                    'instruction': instr.get('instruction', ''),
                    'meta': instr.get('meta', ''),
                    'is_exit_point': instr.get('is_exit_point', instr.get('is_exitprocess', False))
                }
                normalized_instructions.append(normalized)

            traces.append(TraceInfo(
                trace_id=i + 1,
                exit_address=exit_addr,
                instructions=normalized_instructions,
                raw_text=trace_data.get('raw_text', ''),
                instruction_count=len(normalized_instructions)
            ))

        return SampleTraces(
            sha256=sha256,
            source=data.get('source', data.get('source_file', 'unknown')),
            report_url=data.get('report_url'),
            timestamp=data.get('timestamp', ''),
            traces=traces,
            total_traces=len(traces)
        )

    def _load_from_txt(self, sha256: str, txt_file: Path) -> SampleTraces:

        with open(txt_file, 'r', encoding='utf-8') as f:
            content = f.read()

        source = "unknown"
        report_url = None
        timestamp = ""

        source_match = re.search(r'Source:\s*(.+)', content)
        if source_match:
            source = source_match.group(1).strip()

        url_match = re.search(r'Report:\s*(https?://\S+)', content)
        if url_match:
            report_url = url_match.group(1).strip()

        time_match = re.search(r'Timestamp:\s*(.+)', content)
        if time_match:
            timestamp = time_match.group(1).strip()

        trace_pattern = r'TRACE #(\d+) - ExitProcess at ([0-9A-Fa-f]+)'

        traces = []

        trace_matches = list(re.finditer(trace_pattern, content))

        for i, match in enumerate(trace_matches):
            trace_id = int(match.group(1))
            exit_addr = match.group(2)

            start_pos = match.end()
            if i + 1 < len(trace_matches):
                end_pos = trace_matches[i + 1].start()
            else:
                end_pos = len(content)

            trace_content = content[start_pos:end_pos]

            instructions = []
            lines = trace_content.split('\n')

            for line in lines:
                if not line.strip():
                    continue
                if line.strip().startswith('-'):
                    continue
                if 'Address' in line and 'Opcode' in line:
                    continue
                if line.strip().startswith('='):
                    continue

                instr_match = re.match(
                    r'(>>>)?\s*([0-9A-Fa-f]{6,8})\s+([0-9A-Fa-f]+)\s+(.+?)(?:\s{3,}(.*))?$',
                    line
                )
                if instr_match:
                    is_exit = bool(instr_match.group(1))
                    address = instr_match.group(2)
                    opcode = instr_match.group(3)
                    instruction = instr_match.group(4).strip()
                    meta = instr_match.group(5).strip() if instr_match.group(5) else ""

                    instructions.append({
                        'address': address,
                        'opcode': opcode,
                        'instruction': instruction,
                        'meta': meta,
                        'is_exit_point': is_exit
                    })

            traces.append(TraceInfo(
                trace_id=trace_id,
                exit_address=exit_addr,
                instructions=instructions,
                raw_text=trace_content,
                instruction_count=len(instructions)
            ))

        return SampleTraces(
            sha256=sha256,
            source=source,
            report_url=report_url,
            timestamp=timestamp,
            traces=traces,
            total_traces=len(traces)
        )

    def get_trace_for_prompt(self, sha256: str, trace_index: int = 0,
                             max_lines: int = 100) -> Optional[str]:

        sample = self.load_traces(sha256)
        if not sample:
            return None

        if trace_index >= len(sample.traces):
            print(f"[!] Trace index {trace_index} out of range (0-{len(sample.traces)-1})")
            trace_index = 0

        trace = sample.traces[trace_index]

        lines = []
        lines.append(f"SHA256: {sha256}")
        lines.append(f"ExitProcess Address: {trace.exit_address}")
        lines.append(f"Instructions: {trace.instruction_count}")
        lines.append("-" * 80)
        lines.append("Address      Opcode               Instruction")
        lines.append("-" * 80)

        for instr in trace.instructions[:max_lines]:
            prefix = ">>> " if instr.get('is_exit_point') else "    "
            meta_suffix = f"  # {instr['meta']}" if instr.get('meta') else ""
            lines.append(f"{prefix}{instr['address']}  {instr['opcode']:<20} {instr['instruction']}{meta_suffix}")

        if trace.instruction_count > max_lines:
            lines.append(f"... ({trace.instruction_count - max_lines} more instructions)")

        return "\n".join(lines)

    def get_all_traces_for_prompt(self, sha256: str, max_lines_per_trace: int = 160) -> Optional[str]:

        sample = self.load_traces(sha256)
        if not sample:
            return None

        lines = []
        lines.append(f"SHA256: {sha256}")
        lines.append(f"Source: {sample.source}")
        lines.append(f"Total Traces: {sample.total_traces}")
        lines.append("=" * 80)

        for trace in sample.traces:
            lines.append(f"\nTRACE #{trace.trace_id} - ExitProcess at {trace.exit_address}")
            lines.append("-" * 40)

            for instr in trace.instructions[:max_lines_per_trace]:
                prefix = ">>> " if instr.get('is_exit_point') else "    "
                lines.append(f"{prefix}{instr['address']}  {instr['opcode']:<16} {instr['instruction']}")

            if trace.instruction_count > max_lines_per_trace:
                lines.append(f"    ... ({trace.instruction_count - max_lines_per_trace} more)")

        return "\n".join(lines)

    def get_sample_info(self, sha256: str) -> Optional[Dict]:

        sample = self.load_traces(sha256)
        if not sample:
            return None

        return {
            'sha256': sample.sha256,
            'source': sample.source,
            'report_url': sample.report_url,
            'timestamp': sample.timestamp,
            'total_traces': sample.total_traces,
            'trace_instruction_counts': [t.instruction_count for t in sample.traces],
            'exit_addresses': [t.exit_address for t in sample.traces]
        }


def load_trace(sha256: str, trace_dir: Optional[str] = None) -> Optional[str]:

    loader = TraceLoader(trace_dir)
    return loader.get_trace_for_prompt(sha256)


if __name__ == "__main__":
    loader = TraceLoader()

    print("Available samples:")
    samples = loader.list_samples()
    for s in samples:
        print(f"  - {s[:16]}...")

    if samples:
        print(f"\nLoading first sample: {samples[0][:16]}...")
        info = loader.get_sample_info(samples[0])
        if info:
            print(f"  Source: {info['source']}")
            print(f"  Traces: {info['total_traces']}")
            print(f"  Exit addresses: {info['exit_addresses']}")

        print("\nFirst trace for prompt:")
        trace_text = loader.get_trace_for_prompt(samples[0], max_lines=20)
        if trace_text:
            print(trace_text)