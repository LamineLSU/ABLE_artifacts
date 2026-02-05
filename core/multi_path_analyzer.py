
import json
from typing import Dict, List, Tuple, Optional
from datetime import datetime

class APICall:

    def __init__(self, call_data: Dict, process_id: int, sequence_order: int):
        self.api = call_data.get('api', '')
        self.category = call_data.get('category', '')
        self.timestamp = call_data.get('timestamp', '')
        self.arguments = call_data.get('arguments', [])
        self.return_value = call_data.get('return', '')
        self.status = call_data.get('status', False)
        self.thread_id = call_data.get('thread_id', '')
        self.call_id = call_data.get('id', 0)
        self.process_id = process_id
        self.sequence_order = sequence_order

class MultiPathAnalyzer:


    def __init__(self):
        self.process_calls = {}

    def find_all_paths_to_termination(self, behavior_data: Dict) -> Dict[str, List[List[APICall]]]:

        print("[MultiPathAnalyzer] Finding all execution paths to NtTerminateProcess...")

        self._extract_process_calls(behavior_data)

        termination_calls = self._find_ntterminateprocess_calls()

        all_paths = {}
        for term_call in termination_calls:
            term_id = f"p{term_call.process_id}_t{term_call.call_id}"
            paths = self._discover_execution_paths(term_call)
            all_paths[term_id] = paths

            print(f"[MultiPathAnalyzer] Found {len(paths)} paths to {term_call.api} in process {term_call.process_id}")

        return all_paths

    def _extract_process_calls(self, behavior_data: Dict):

        processes_data = behavior_data.get('processes', [])

        for proc_data in processes_data:
            process_id = proc_data.get('process_id')
            calls_data = proc_data.get('calls', [])

            sorted_calls = sorted(calls_data, key=lambda x: x.get('id', 0))

            process_api_calls = []
            for i, call_data in enumerate(sorted_calls):
                api_call = APICall(call_data, process_id, i)
                process_api_calls.append(api_call)

            self.process_calls[process_id] = process_api_calls
            print(f"[MultiPathAnalyzer] Process {process_id}: {len(process_api_calls)} API calls")

    def _find_ntterminateprocess_calls(self) -> List[APICall]:

        termination_calls = []

        for process_id, api_calls in self.process_calls.items():
            for call in api_calls:
                if call.api == 'NtTerminateProcess':
                    termination_calls.append(call)

        print(f"[MultiPathAnalyzer] Found {len(termination_calls)} NtTerminateProcess calls")
        return termination_calls

    def _discover_execution_paths(self, termination_call: APICall) -> List[List[APICall]]:

        process_id = termination_call.process_id
        process_calls = self.process_calls.get(process_id, [])

        term_position = -1
        for i, call in enumerate(process_calls):
            if call.call_id == termination_call.call_id:
                term_position = i
                break

        if term_position == -1:
            return []

        preceding_calls = process_calls[:term_position]

        branch_paths = self._find_branch_paths(preceding_calls, termination_call)

        thread_paths = self._find_thread_paths(preceding_calls, termination_call)

        time_paths = self._find_time_window_paths(preceding_calls, termination_call)

        all_paths = branch_paths + thread_paths + time_paths
        unique_paths = self._remove_duplicate_paths(all_paths)

        return unique_paths

    def _find_branch_paths(self, preceding_calls: List[APICall], termination_call: APICall) -> List[List[APICall]]:

        branch_apis = {
            'GetSystemTime', 'GetUserDefaultLCID', 'GetComputerNameW',
            'GetSystemInfo', 'GetVersionExW', 'GetTickCount',
            'RegOpenKeyExW', 'RegQueryValueExW', 'GetModuleHandleW'
        }

        paths = []

        for branch_api in branch_apis:
            branch_calls = [call for call in preceding_calls if call.api == branch_api]

            for branch_call in branch_calls:
                path = self._build_path_from_branch(branch_call, preceding_calls, termination_call)
                if path and len(path) >= 2:
                    paths.append(path)

        return paths

    def _build_path_from_branch(self, branch_call: APICall, all_calls: List[APICall], termination_call: APICall) -> List[APICall]:

        intermediate_calls = []

        for call in all_calls:
            if (call.sequence_order > branch_call.sequence_order and
                call.sequence_order < termination_call.sequence_order):

                time_to_term = self._calculate_time_diff(call.timestamp, termination_call.timestamp)

                if time_to_term <= 2.0:
                    intermediate_calls.append(call)

        intermediate_calls.sort(key=lambda x: x.sequence_order)

        path = [branch_call]

        if intermediate_calls:
            selected_intermediates = self._select_relevant_intermediates(intermediate_calls, 8)
            path.extend(selected_intermediates)

        return path

    def _find_thread_paths(self, preceding_calls: List[APICall], termination_call: APICall) -> List[List[APICall]]:

        paths = []

        thread_groups = {}
        for call in preceding_calls:
            if call.thread_id not in thread_groups:
                thread_groups[call.thread_id] = []
            thread_groups[call.thread_id].append(call)

        for thread_id, thread_calls in thread_groups.items():
            if len(thread_calls) >= 2:
                thread_calls.sort(key=lambda x: x.sequence_order)
                recent_calls = thread_calls[-10:]
                paths.append(recent_calls)

        return paths

    def _find_time_window_paths(self, preceding_calls: List[APICall], termination_call: APICall) -> List[List[APICall]]:

        paths = []

        time_windows = [0.1, 0.5, 1.0]

        for window in time_windows:
            window_calls = []
            for call in preceding_calls:
                time_diff = self._calculate_time_diff(call.timestamp, termination_call.timestamp)
                if time_diff <= window:
                    window_calls.append(call)

            if len(window_calls) >= 2:
                window_calls.sort(key=lambda x: x.sequence_order)
                paths.append(window_calls)

        return paths

    def _select_relevant_intermediates(self, intermediate_calls: List[APICall], max_count: int) -> List[APICall]:

        priority_patterns = {
            'system': 3,
            'registry': 3,
            'process': 2,
            'memory': 2,
            'threading': 1,
            'file': 1
        }

        scored_calls = []
        for call in intermediate_calls:
            score = priority_patterns.get(call.category, 0)

            if any(pattern in call.api for pattern in ['Get', 'Query', 'Check', 'Test']):
                score += 1
            if 'Default' in call.api or 'System' in call.api:
                score += 1

            scored_calls.append((call, score))

        scored_calls.sort(key=lambda x: x[1], reverse=True)
        return [call for call, score in scored_calls[:max_count]]

    def _remove_duplicate_paths(self, all_paths: List[List[APICall]]) -> List[List[APICall]]:

        unique_paths = []
        seen_patterns = set()

        for path in all_paths:
            pattern = tuple(call.api for call in path)

            if pattern not in seen_patterns and len(path) >= 2:
                seen_patterns.add(pattern)
                unique_paths.append(path)

        unique_paths.sort(key=lambda p: len(p), reverse=True)
        return unique_paths[:8]

    def _calculate_time_diff(self, earlier_time: str, later_time: str) -> float:

        try:
            earlier = datetime.strptime(earlier_time, "%Y-%m-%d %H:%M:%S,%f")
            later = datetime.strptime(later_time, "%Y-%m-%d %H:%M:%S,%f")
            return (later - earlier).total_seconds()
        except:
            return 0.0

    def generate_multi_path_analysis_prompt(self, termination_call: APICall, all_paths: List[List[APICall]]) -> str:


        prompt = f"""MULTI-PATH EVASION ANALYSIS

SITUATION: Malware called NtTerminateProcess - likely an evasion technique
Process ID: {termination_call.process_id}
Termination Time: {termination_call.timestamp}

We found {len(all_paths)} DIFFERENT EXECUTION PATHS that could lead to this termination:

"""

        for path_idx, path in enumerate(all_paths, 1):
            prompt += f"\n=== EXECUTION PATH {path_idx} ===\n"

            for step_idx, api_call in enumerate(path, 1):
                time_diff = self._calculate_time_diff(api_call.timestamp, termination_call.timestamp)
                prompt += f"{step_idx}. {api_call.api} ({api_call.category})\n"
                prompt += f"   Time before termination: {time_diff:.3f}s\n"
                prompt += f"   Return: {api_call.return_value}\n"

                if api_call.arguments:
                    key_args = []
                    for arg in api_call.arguments[:2]:
                        if isinstance(arg, dict) and 'value' in arg:
                            key_args.append(str(arg['value'])[:50])
                    if key_args:
                        prompt += f"   Args: {', '.join(key_args)}\n"
                prompt += "\n"

        prompt += f"""
MULTI-PATH ANALYSIS TASKS:

1. IDENTIFY DECISION BRANCHES:
   - Which paths represent different evasion conditions?
   - Are these checking for different environmental factors?
   - Do different paths check different aspects (time, locale, system info)?

2. FIND CRITICAL DECISION APIS:
   - In each path, which API likely contains the evasion trigger?
   - Which APIs have return values that could cause termination decisions?
   - What specific checks could each path be performing?

3. COMPARE EVASION STRATEGIES:
   - Do the different paths check for different threats (debugger vs VM vs sandbox)?
   - Are these redundant checks or different evasion techniques?
   - Which path is most likely to be the primary evasion method?

4. DEBUGGING STRATEGY:
   - Which path should be debugged first (highest priority)?
   - In each path, which specific API should be traced?
   - What return values/arguments should be monitored?

OUTPUT FORMAT:
PATH_ANALYSIS:
Path 1: [Brief description of what this path likely checks]
Path 2: [Brief description of what this path likely checks]
...

CRITICAL_APIS: [List of 2-3 most important APIs across all paths]
PRIMARY_EVASION: [Which path/API is most likely the main evasion technique]
DEBUG_PRIORITY: [Which path and API to debug first]
EVASION_TYPE: [Overall evasion type: anti-debug/anti-VM/anti-sandbox/environment]
CONFIDENCE: [High/Medium/Low confidence in this analysis]"""

        return prompt

def analyze_multiple_termination_paths(behavior_data: Dict) -> Tuple[Dict, List[str]]:

    analyzer = MultiPathAnalyzer()
    all_paths = analyzer.find_all_paths_to_termination(behavior_data)

    llm_prompts = []
    analysis_data = {}

    for term_id, paths in all_paths.items():
        if paths:
            process_id = int(term_id.split('_')[0][1:])
            process_calls = analyzer.process_calls.get(process_id, [])

            termination_call = None
            for call in process_calls:
                if call.api == 'NtTerminateProcess':
                    termination_call = call
                    break

            if termination_call:
                llm_prompt = analyzer.generate_multi_path_analysis_prompt(termination_call, paths)
                llm_prompts.append(llm_prompt)

                analysis_data[term_id] = {
                    "termination_call": termination_call,
                    "execution_paths": paths,
                    "llm_prompt": llm_prompt,
                    "path_count": len(paths)
                }

    return analysis_data, llm_prompts