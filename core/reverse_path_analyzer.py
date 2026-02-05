
import json
from typing import Dict, List, Tuple, Optional
from datetime import datetime

class APICall:

    def __init__(self, call_data: Dict, process_id: int):
        self.api = call_data.get('api', '')
        self.category = call_data.get('category', '')
        self.timestamp = call_data.get('timestamp', '')
        self.arguments = call_data.get('arguments', [])
        self.return_value = call_data.get('return', '')
        self.status = call_data.get('status', False)
        self.thread_id = call_data.get('thread_id', '')
        self.call_id = call_data.get('id', 0)
        self.process_id = process_id

    def to_dict(self) -> Dict:

        return {
            "api": self.api,
            "category": self.category,
            "timestamp": self.timestamp,
            "arguments": self.arguments[:3],
            "return_value": self.return_value,
            "status": self.status,
            "process_id": self.process_id
        }

class ReversePathAnalyzer:


    TERMINATION_APIS = {
        'NtTerminateProcess'
    }

    def __init__(self):
        self.all_api_calls = []

    def analyze_cape_behavior(self, behavior_data: Dict) -> List[Dict]:

        print("[ReversePathAnalyzer] Starting reverse path analysis...")

        self._extract_all_api_calls(behavior_data)

        termination_points = self._find_termination_points()

        analysis_results = []
        for term_call in termination_points:
            backward_chain = self._trace_backward_chain(term_call)
            if backward_chain:
                analysis_data = self._prepare_llm_analysis(term_call, backward_chain)
                analysis_results.append(analysis_data)

        print(f"[ReversePathAnalyzer] Found {len(analysis_results)} termination chains to analyze")
        return analysis_results

    def _extract_all_api_calls(self, behavior_data: Dict):

        processes_data = behavior_data.get('processes', [])

        for proc_data in processes_data:
            process_id = proc_data.get('process_id')
            calls_data = proc_data.get('calls', [])

            for call_data in calls_data:
                api_call = APICall(call_data, process_id)
                self.all_api_calls.append(api_call)

        self.all_api_calls.sort(key=lambda x: (x.timestamp, x.process_id, x.call_id))
        print(f"[ReversePathAnalyzer] Extracted {len(self.all_api_calls)} total API calls")

    def _find_termination_points(self) -> List[APICall]:

        termination_points = []

        for api_call in self.all_api_calls:
            if api_call.api in self.TERMINATION_APIS:
                termination_points.append(api_call)

        print(f"[ReversePathAnalyzer] Found {len(termination_points)} termination points")
        return termination_points

    def _trace_backward_chain(self, termination_call: APICall, window_size: int = 20) -> List[APICall]:

        term_index = -1
        for i, call in enumerate(self.all_api_calls):
            if (call.process_id == termination_call.process_id and
                call.call_id == termination_call.call_id):
                term_index = i
                break

        if term_index == -1:
            return []

        backward_chain = []
        for i in range(max(0, term_index - window_size), term_index):
            call = self.all_api_calls[i]
            if call.process_id == termination_call.process_id:
                backward_chain.append(call)

        print(f"[ReversePathAnalyzer] Traced {len(backward_chain)} APIs before {termination_call.api}")
        return backward_chain

    def _prepare_llm_analysis(self, termination_call: APICall, backward_chain: List[APICall]) -> Dict:


        if backward_chain:
            total_time_span = self._calculate_time_diff(
                backward_chain[0].timestamp,
                termination_call.timestamp
            )
        else:
            total_time_span = 0.0

        analysis_data = {
            "termination_point": {
                "api": termination_call.api,
                "process_id": termination_call.process_id,
                "timestamp": termination_call.timestamp,
                "details": termination_call.to_dict()
            },
            "backward_chain": [],
            "chain_stats": {
                "total_apis": len(backward_chain),
                "time_span_seconds": total_time_span,
                "process_id": termination_call.process_id
            },
            "llm_prompt": ""
        }

        for i, api_call in enumerate(backward_chain):
            time_before_term = self._calculate_time_diff(
                api_call.timestamp,
                termination_call.timestamp
            )

            analysis_data["backward_chain"].append({
                "sequence": i + 1,
                "api_details": api_call.to_dict(),
                "time_before_termination": time_before_term
            })

        analysis_data["llm_prompt"] = self._generate_llm_prompt(termination_call, backward_chain)

        return analysis_data

    def _calculate_time_diff(self, earlier_time: str, later_time: str) -> float:

        try:
            earlier = datetime.strptime(earlier_time, "%Y-%m-%d %H:%M:%S,%f")
            later = datetime.strptime(later_time, "%Y-%m-%d %H:%M:%S,%f")
            return (later - earlier).total_seconds()
        except:
            return 0.0

    def _generate_llm_prompt(self, termination_call: APICall, backward_chain: List[APICall]) -> str:


        prompt = f"""FOCUSED NtTerminateProcess EVASION ANALYSIS

CRITICAL EVASION POINT: Malware called NtTerminateProcess to exit early
Process ID: {termination_call.process_id}
Termination Time: {termination_call.timestamp}

This is likely an EVASION TECHNIQUE - the malware detected something and decided to terminate.

API CHAIN LEADING TO NtTerminateProcess ({len(backward_chain)} calls):
"""

        for i, api_call in enumerate(backward_chain):
            time_diff = self._calculate_time_diff(api_call.timestamp, termination_call.timestamp)

            prompt += f"\n{i+1:2d}. {api_call.api} ({api_call.category})"
            prompt += f"    [{time_diff:.3f}s before termination]"
            prompt += f"    Return: {api_call.return_value}"

            if api_call.arguments:
                key_args = []
                for arg in api_call.arguments[:2]:
                    if isinstance(arg, dict) and 'value' in arg:
                        key_args.append(arg['value'])
                if key_args:
                    prompt += f"    Args: {', '.join(str(arg) for arg in key_args)}"

        prompt += f"""

FOCUSED ANALYSIS TASKS:
1. FIND THE EVASION TRIGGER:
   - Which API(s) in this chain likely detected the analysis environment?
   - What specific return values or checks triggered the decision to call NtTerminateProcess?
   - Look for environment checks, VM detection, debug detection, timing checks

2. IDENTIFY DECISION VARIABLES:
   - Which API returns a value that could be different in a real environment?
   - What arguments or system responses indicate sandbox/VM/debug detection?
   - Which APIs are checking system state that could vary?

3. FORCE EXECUTION STRATEGY:
   - To prevent this NtTerminateProcess call, which specific APIs should be modified?
   - What return values should be changed to fool the evasion check?
   - Which API is the PRIMARY decision point?

4. DEBUGGER TARGETING:
   - Which 2-3 APIs should be traced with a debugger to understand the evasion?
   - What specific parameters/returns need monitoring?

OUTPUT FORMAT:
SUSPICIOUS_APIS: [List of 2-3 most critical API names that triggered NtTerminateProcess]
EVASION_TYPE: [What the malware is detecting: anti-debug/anti-VM/anti-sandbox/timing]
DECISION_LOGIC: [How these APIs led to the termination decision]
FORCE_EXECUTION: [Specific API modifications needed to prevent termination]
DEBUG_PRIORITY: [Top 2 APIs to trace with debugger, most critical first]
CONFIDENCE: [High/Medium/Low confidence in this evasion analysis]"""

        return prompt

def create_reverse_path_analysis(behavior_data: Dict) -> Tuple[List[Dict], Dict]:

    analyzer = ReversePathAnalyzer()
    analysis_results = analyzer.analyze_cape_behavior(behavior_data)

    suspicious_apis = []
    analysis_summary = {
        "total_termination_points": len(analysis_results),
        "analysis_method": "reverse_path_tracing",
        "termination_apis_found": [],
        "ready_for_llm": True
    }

    for result in analysis_results:
        term_api = result["termination_point"]["api"]
        analysis_summary["termination_apis_found"].append(term_api)

        for chain_item in result["backward_chain"]:
            api_details = chain_item["api_details"]
            suspicious_apis.append({
                "api": api_details["api"],
                "category": api_details["category"],
                "process_id": api_details["process_id"],
                "confidence": 0.7,
                "evasion_type": "unknown_pending_llm_analysis",
                "reasoning": f"Part of API chain leading to {term_api}",
                "time_before_termination": chain_item["time_before_termination"],
                "llm_analysis_needed": True
            })

    return suspicious_apis, analysis_summary