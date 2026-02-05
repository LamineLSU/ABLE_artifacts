
import json
import time
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field, asdict
import threading


@dataclass
class LLMQuery:

    query_id: str
    timestamp: str
    iteration: int
    prompt_version: str

    prompt_text: str
    prompt_length: int
    prompt_tokens: int

    response_text: str
    response_length: int
    response_tokens: int

    query_start_time: float
    query_end_time: float
    query_duration_seconds: float

    model_name: str
    model_provider: str
    temperature: float

    pattern_type: str
    confidence: int
    yara_rule: str
    opcodes_generic: str
    opcodes_specific: str


@dataclass
class CAPEAnalysis:

    task_id: int
    analysis_type: str

    vm_host: Optional[str] = None
    vm_name: Optional[str] = None

    submit_time: float = 0.0
    complete_time: float = 0.0
    duration_seconds: float = 0.0

    signatures_count: int = 0
    signature_names: List[str] = field(default_factory=list)
    rule_hit: bool = False

    yara_rule: Optional[str] = None
    yara_file: Optional[str] = None


@dataclass
class IterationRecord:

    iteration_number: int
    prompt_version: str

    llm_query: LLMQuery

    cape_analysis: Optional[CAPEAnalysis]

    success: bool
    new_signatures: int
    new_signature_names: List[str]

    feedback_given: Optional[str] = None
    evolution_reasoning: Optional[str] = None


@dataclass
class PromptStrategyEvaluation:

    prompt_version: str
    prompt_name: str

    iterations: List[IterationRecord]
    total_iterations: int
    iterations_to_success: Optional[int]

    total_time_seconds: float
    avg_query_time_seconds: float
    avg_analysis_time_seconds: float

    total_input_tokens: int
    total_output_tokens: int
    total_tokens: int

    success: bool
    best_score: int
    best_iteration: Optional[int]

    final_yara_rule: Optional[str]
    final_new_signatures: List[str]


@dataclass
class SampleEvaluation:

    sha256: str
    sample_path: Optional[str]
    evaluation_id: str
    timestamp: str

    file_size: Optional[int] = None
    malware_family: Optional[str] = None

    model_name: str = ""
    model_provider: str = ""
    temperature: float = 0.7

    baseline_task_id: Optional[int] = None
    baseline_signatures: List[str] = field(default_factory=list)
    baseline_signature_count: int = 0
    baseline_time_seconds: float = 0.0

    prompt_strategies: Dict[str, PromptStrategyEvaluation] = field(default_factory=dict)

    total_time_seconds: float = 0.0
    successful_strategies: List[str] = field(default_factory=list)
    best_strategy: Optional[str] = None
    best_score: int = 0
    fastest_success_strategy: Optional[str] = None
    fastest_success_time: Optional[float] = None

    total_llm_queries: int = 0
    total_cape_analyses: int = 0
    total_input_tokens: int = 0
    total_output_tokens: int = 0


class EvaluationLogger:


    def __init__(self, output_dir: str = "evaluation_logs"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.current_evaluation: Optional[SampleEvaluation] = None

        self._strategies: Dict[str, PromptStrategyEvaluation] = {}
        self._iterations: Dict[str, IterationRecord] = {}
        self._strategy_start_times: Dict[str, float] = {}
        self._query_start_times: Dict[str, float] = {}
        self._analysis_start_times: Dict[str, float] = {}

        self.current_strategy: Optional[PromptStrategyEvaluation] = None
        self.current_iteration: Optional[IterationRecord] = None

        self._query_start_time: Optional[float] = None
        self._analysis_start_time: Optional[float] = None
        self._strategy_start_time: Optional[float] = None
        self._evaluation_start_time: Optional[float] = None

        self._lock = threading.Lock()

    def start_evaluation(self, sha256: str, sample_path: Optional[str] = None,
                        model_name: str = "", model_provider: str = "",
                        temperature: float = 0.7) -> str:

        with self._lock:
            eval_id = f"{sha256[:16]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

            self.current_evaluation = SampleEvaluation(
                sha256=sha256,
                sample_path=sample_path,
                evaluation_id=eval_id,
                timestamp=datetime.now().isoformat(),
                model_name=model_name,
                model_provider=model_provider,
                temperature=temperature
            )

            if sample_path and Path(sample_path).exists():
                self.current_evaluation.file_size = Path(sample_path).stat().st_size

            self._evaluation_start_time = time.time()

            return eval_id

    def log_baseline(self, task_id: int, signatures: List[str],
                     duration_seconds: float):

        with self._lock:
            if self.current_evaluation:
                self.current_evaluation.baseline_task_id = task_id
                self.current_evaluation.baseline_signatures = signatures
                self.current_evaluation.baseline_signature_count = len(signatures)
                self.current_evaluation.baseline_time_seconds = duration_seconds

    def start_prompt_strategy(self, prompt_version: str, prompt_name: str = ""):

        with self._lock:
            strategy = PromptStrategyEvaluation(
                prompt_version=prompt_version,
                prompt_name=prompt_name or prompt_version,
                iterations=[],
                total_iterations=0,
                iterations_to_success=None,
                total_time_seconds=0.0,
                avg_query_time_seconds=0.0,
                avg_analysis_time_seconds=0.0,
                total_input_tokens=0,
                total_output_tokens=0,
                total_tokens=0,
                success=False,
                best_score=0,
                best_iteration=None,
                final_yara_rule=None,
                final_new_signatures=[]
            )
            self._strategies[prompt_version] = strategy
            self._strategy_start_times[prompt_version] = time.time()

            self.current_strategy = strategy
            self._strategy_start_time = time.time()

    def start_iteration(self, iteration_number: int, prompt_version: str = None):

        with self._lock:
            if prompt_version is None:
                prompt_version = self.current_strategy.prompt_version if self.current_strategy else ""

            iteration = IterationRecord(
                iteration_number=iteration_number,
                prompt_version=prompt_version,
                llm_query=None,
                cape_analysis=None,
                success=False,
                new_signatures=0,
                new_signature_names=[],
                feedback_given=None,
                evolution_reasoning=None
            )

            self._iterations[prompt_version] = iteration

            self.current_iteration = iteration

    def start_llm_query(self, prompt_version: str = None):

        now = time.time()
        if prompt_version:
            with self._lock:
                self._query_start_times[prompt_version] = now
        self._query_start_time = now

    def log_llm_query(self, prompt_text: str, response_text: str,
                      model_name: str, model_provider: str,
                      temperature: float = 0.7,
                      pattern_type: str = "", confidence: int = 0,
                      yara_rule: str = "", opcodes_generic: str = "",
                      opcodes_specific: str = "",
                      input_tokens: Optional[int] = None,
                      output_tokens: Optional[int] = None,
                      prompt_version: str = None):

        with self._lock:
            query_end = time.time()

            if prompt_version and prompt_version in self._query_start_times:
                query_start = self._query_start_times[prompt_version]
            else:
                query_start = self._query_start_time or query_end

            if prompt_version and prompt_version in self._iterations:
                current_iter = self._iterations[prompt_version]
                current_strat = self._strategies.get(prompt_version)
            else:
                current_iter = self.current_iteration
                current_strat = self.current_strategy

            est_input_tokens = input_tokens or len(prompt_text) // 4
            est_output_tokens = output_tokens or len(response_text) // 4

            query = LLMQuery(
                query_id=hashlib.md5(f"{prompt_text[:100]}{query_end}".encode()).hexdigest()[:12],
                timestamp=datetime.now().isoformat(),
                iteration=current_iter.iteration_number if current_iter else 0,
                prompt_version=prompt_version or (current_strat.prompt_version if current_strat else ""),
                prompt_text=prompt_text,
                prompt_length=len(prompt_text),
                prompt_tokens=est_input_tokens,
                response_text=response_text,
                response_length=len(response_text),
                response_tokens=est_output_tokens,
                query_start_time=query_start,
                query_end_time=query_end,
                query_duration_seconds=query_end - query_start,
                model_name=model_name,
                model_provider=model_provider,
                temperature=temperature,
                pattern_type=pattern_type,
                confidence=confidence,
                yara_rule=yara_rule,
                opcodes_generic=opcodes_generic,
                opcodes_specific=opcodes_specific
            )

            if current_iter:
                current_iter.llm_query = query

            if current_strat:
                current_strat.total_input_tokens += est_input_tokens
                current_strat.total_output_tokens += est_output_tokens
                current_strat.total_tokens += est_input_tokens + est_output_tokens

            if self.current_evaluation:
                self.current_evaluation.total_input_tokens += est_input_tokens
                self.current_evaluation.total_output_tokens += est_output_tokens
                self.current_evaluation.total_llm_queries += 1

    def start_cape_analysis(self, prompt_version: str = None):

        now = time.time()
        if prompt_version:
            with self._lock:
                self._analysis_start_times[prompt_version] = now
        self._analysis_start_time = now

    def log_cape_analysis(self, task_id: int, analysis_type: str,
                          signatures: List[str], rule_hit: bool = False,
                          yara_rule: Optional[str] = None,
                          yara_file: Optional[str] = None,
                          prompt_version: str = None,
                          vm_host: str = None,
                          vm_name: str = None):

        with self._lock:
            analysis_end = time.time()

            if prompt_version and prompt_version in self._analysis_start_times:
                analysis_start = self._analysis_start_times[prompt_version]
            else:
                analysis_start = self._analysis_start_time or analysis_end

            if prompt_version and prompt_version in self._iterations:
                current_iter = self._iterations[prompt_version]
            else:
                current_iter = self.current_iteration

            analysis = CAPEAnalysis(
                task_id=task_id,
                analysis_type=analysis_type,
                vm_host=vm_host,
                vm_name=vm_name,
                submit_time=analysis_start,
                complete_time=analysis_end,
                duration_seconds=analysis_end - analysis_start,
                signatures_count=len(signatures),
                signature_names=signatures,
                rule_hit=rule_hit,
                yara_rule=yara_rule,
                yara_file=yara_file
            )

            if current_iter:
                current_iter.cape_analysis = analysis

            if self.current_evaluation:
                self.current_evaluation.total_cape_analyses += 1

    def log_iteration_result(self, success: bool, new_signatures: int,
                             new_signature_names: List[str],
                             feedback: Optional[str] = None,
                             evolution_reasoning: Optional[str] = None,
                             prompt_version: str = None):

        with self._lock:
            if prompt_version and prompt_version in self._iterations:
                current_iter = self._iterations[prompt_version]
                current_strat = self._strategies.get(prompt_version)
            else:
                current_iter = self.current_iteration
                current_strat = self.current_strategy

            if current_iter:
                current_iter.success = success
                current_iter.new_signatures = new_signatures
                current_iter.new_signature_names = new_signature_names
                current_iter.feedback_given = feedback
                current_iter.evolution_reasoning = evolution_reasoning

                if current_strat:
                    current_strat.iterations.append(current_iter)
                    current_strat.total_iterations += 1

                    if new_signatures > current_strat.best_score:
                        current_strat.best_score = new_signatures
                        current_strat.best_iteration = current_iter.iteration_number

                    if success and current_strat.iterations_to_success is None:
                        current_strat.iterations_to_success = current_iter.iteration_number + 1
                        current_strat.success = True

    def end_prompt_strategy(self, final_yara_rule: Optional[str] = None,
                            final_new_signatures: Optional[List[str]] = None,
                            prompt_version: str = None):

        with self._lock:
            if prompt_version and prompt_version in self._strategies:
                current_strat = self._strategies[prompt_version]
                strategy_start = self._strategy_start_times.get(prompt_version, time.time())
            else:
                current_strat = self.current_strategy
                strategy_start = self._strategy_start_time or time.time()

            if current_strat:
                strategy_end = time.time()

                current_strat.total_time_seconds = strategy_end - strategy_start
                current_strat.final_yara_rule = final_yara_rule
                current_strat.final_new_signatures = final_new_signatures or []

                query_times = [it.llm_query.query_duration_seconds
                              for it in current_strat.iterations
                              if it.llm_query]
                analysis_times = [it.cape_analysis.duration_seconds
                                 for it in current_strat.iterations
                                 if it.cape_analysis]

                if query_times:
                    current_strat.avg_query_time_seconds = sum(query_times) / len(query_times)
                if analysis_times:
                    current_strat.avg_analysis_time_seconds = sum(analysis_times) / len(analysis_times)

                if self.current_evaluation:
                    self.current_evaluation.prompt_strategies[current_strat.prompt_version] = current_strat

                    if current_strat.success:
                        if current_strat.prompt_version not in self.current_evaluation.successful_strategies:
                            self.current_evaluation.successful_strategies.append(current_strat.prompt_version)

                        if current_strat.best_score > self.current_evaluation.best_score:
                            self.current_evaluation.best_score = current_strat.best_score
                            self.current_evaluation.best_strategy = current_strat.prompt_version

                        if (self.current_evaluation.fastest_success_time is None or
                            current_strat.total_time_seconds < self.current_evaluation.fastest_success_time):
                            self.current_evaluation.fastest_success_time = current_strat.total_time_seconds
                            self.current_evaluation.fastest_success_strategy = current_strat.prompt_version

    def end_evaluation(self) -> str:

        with self._lock:
            if not self.current_evaluation:
                return ""

            eval_end = time.time()
            eval_start = self._evaluation_start_time or eval_end
            self.current_evaluation.total_time_seconds = eval_end - eval_start

            eval_data = self._to_dict(self.current_evaluation)

            eval_folder = self.output_dir / self.current_evaluation.evaluation_id
            eval_folder.mkdir(parents=True, exist_ok=True)

            eval_file = eval_folder / "evaluation_complete.json"
            with open(eval_file, 'w', encoding='utf-8') as f:
                json.dump(eval_data, f, indent=2, default=str)

            summary = self._generate_summary()
            summary_file = eval_folder / "evaluation_summary.json"
            with open(summary_file, 'w', encoding='utf-8') as f:
                json.dump(summary, f, indent=2, default=str)

            for version, strategy in self.current_evaluation.prompt_strategies.items():
                strategy_file = eval_folder / f"strategy_{version}.json"
                with open(strategy_file, 'w', encoding='utf-8') as f:
                    json.dump(self._to_dict(strategy), f, indent=2, default=str)

            prompts_file = eval_folder / "all_prompts_responses.json"
            prompts_data = self._extract_prompts_responses()
            with open(prompts_file, 'w', encoding='utf-8') as f:
                json.dump(prompts_data, f, indent=2, default=str)

            eval_id = self.current_evaluation.evaluation_id
            self.current_evaluation = None

            return str(eval_folder)

    def _to_dict(self, obj) -> dict:

        if hasattr(obj, '__dataclass_fields__'):
            result = {}
            for field_name in obj.__dataclass_fields__:
                value = getattr(obj, field_name)
                result[field_name] = self._to_dict(value)
            return result
        elif isinstance(obj, dict):
            return {k: self._to_dict(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._to_dict(item) for item in obj]
        else:
            return obj

    def _generate_summary(self) -> dict:

        if not self.current_evaluation:
            return {}

        eval_data = self.current_evaluation

        strategy_summaries = {}
        for version, strategy in eval_data.prompt_strategies.items():
            strategy_summaries[version] = {
                "success": strategy.success,
                "iterations_to_success": strategy.iterations_to_success,
                "total_iterations": strategy.total_iterations,
                "best_score": strategy.best_score,
                "total_time_seconds": round(strategy.total_time_seconds, 2),
                "avg_query_time_seconds": round(strategy.avg_query_time_seconds, 2),
                "avg_analysis_time_seconds": round(strategy.avg_analysis_time_seconds, 2),
                "total_tokens": strategy.total_tokens,
                "input_tokens": strategy.total_input_tokens,
                "output_tokens": strategy.total_output_tokens
            }

        return {
            "evaluation_id": eval_data.evaluation_id,
            "sha256": eval_data.sha256,
            "timestamp": eval_data.timestamp,

            "model_info": {
                "name": eval_data.model_name,
                "provider": eval_data.model_provider,
                "temperature": eval_data.temperature
            },

            "baseline": {
                "task_id": eval_data.baseline_task_id,
                "signature_count": eval_data.baseline_signature_count,
                "time_seconds": round(eval_data.baseline_time_seconds, 2)
            },

            "overall_results": {
                "total_time_seconds": round(eval_data.total_time_seconds, 2),
                "strategies_tested": len(eval_data.prompt_strategies),
                "successful_strategies": eval_data.successful_strategies,
                "best_strategy": eval_data.best_strategy,
                "best_score": eval_data.best_score,
                "fastest_success_strategy": eval_data.fastest_success_strategy,
                "fastest_success_time": round(eval_data.fastest_success_time, 2) if eval_data.fastest_success_time else None
            },

            "resource_usage": {
                "total_llm_queries": eval_data.total_llm_queries,
                "total_cape_analyses": eval_data.total_cape_analyses,
                "total_input_tokens": eval_data.total_input_tokens,
                "total_output_tokens": eval_data.total_output_tokens,
                "total_tokens": eval_data.total_input_tokens + eval_data.total_output_tokens
            },

            "per_strategy": strategy_summaries
        }

    def _extract_prompts_responses(self) -> dict:

        if not self.current_evaluation:
            return {}

        all_queries = []
        for version, strategy in self.current_evaluation.prompt_strategies.items():
            for iteration in strategy.iterations:
                if iteration.llm_query:
                    q = iteration.llm_query
                    all_queries.append({
                        "query_id": q.query_id,
                        "prompt_version": version,
                        "iteration": iteration.iteration_number,
                        "prompt_text": q.prompt_text,
                        "response_text": q.response_text,
                        "yara_rule": q.yara_rule,
                        "pattern_type": q.pattern_type,
                        "confidence": q.confidence,
                        "query_duration_seconds": round(q.query_duration_seconds, 2),
                        "prompt_tokens": q.prompt_tokens,
                        "response_tokens": q.response_tokens,
                        "feedback_given": iteration.feedback_given,
                        "evolution_reasoning": iteration.evolution_reasoning,
                        "success": iteration.success,
                        "new_signatures": iteration.new_signatures
                    })

        return {
            "evaluation_id": self.current_evaluation.evaluation_id,
            "total_queries": len(all_queries),
            "queries": all_queries
        }


_global_logger: Optional[EvaluationLogger] = None


def get_evaluation_logger(output_dir: str = "evaluation_logs") -> EvaluationLogger:

    global _global_logger
    if _global_logger is None:
        _global_logger = EvaluationLogger(output_dir)
    return _global_logger


def reset_evaluation_logger():

    global _global_logger
    _global_logger = None
