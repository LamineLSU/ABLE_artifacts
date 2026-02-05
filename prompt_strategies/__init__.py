
from .prompt_loader import (
    PromptLoader,
    PromptMetadata,
    get_loader,

    get_prompt,
    format_prompt,
    list_prompts,
    get_prompt_metadata,
    get_all_prompts_for_evaluation,
    get_prompt_summary,

    RECOMMENDED_PROMPT,
)


_legacy_prompts = {}
_legacy_exports = []

try:
    from . import prompt_versions as _pv

    if hasattr(_pv, 'PROMPT_V1_SIMPLE'):
        _legacy_prompts = {
            'PROMPT_V1_SIMPLE': getattr(_pv, 'PROMPT_V1_SIMPLE', None),
            'PROMPT_V2_COUNTERFACTUAL': getattr(_pv, 'PROMPT_V2_COUNTERFACTUAL', None),
            'PROMPT_V3_ADVERSARIAL': getattr(_pv, 'PROMPT_V3_ADVERSARIAL', None),
            'PROMPT_V4_PATTERN_DECOMPOSITION': getattr(_pv, 'PROMPT_V4_PATTERN_DECOMPOSITION', None),
            'PROMPT_V5_EVOLUTIONARY': getattr(_pv, 'PROMPT_V5_EVOLUTIONARY', None),
            'PROMPT_V6_HYBRID': getattr(_pv, 'PROMPT_V6_HYBRID', None),
            'PROMPT_V7_OPTIMAL': getattr(_pv, 'PROMPT_V7_OPTIMAL', None),
            'PROMPT_V8_ADAPTIVE_COUNTERFACTUAL': getattr(_pv, 'PROMPT_V8_ADAPTIVE_COUNTERFACTUAL', None),
            'PROMPT_V9_COUNTERFACTUAL_WILDCARDS': getattr(_pv, 'PROMPT_V9_COUNTERFACTUAL_WILDCARDS', None),
            'PROMPT_V10_ADVERSARIAL_DUAL': getattr(_pv, 'PROMPT_V10_ADVERSARIAL_DUAL', None),
        }
        _legacy_exports = [k for k, v in _legacy_prompts.items() if v is not None]

        for name, value in _legacy_prompts.items():
            if value is not None:
                globals()[name] = value

except ImportError:
    pass


__all__ = [
    'PromptLoader',
    'PromptMetadata',
    'get_loader',
    'get_prompt',
    'format_prompt',
    'list_prompts',
    'get_prompt_metadata',
    'get_all_prompts_for_evaluation',
    'get_prompt_summary',
    'RECOMMENDED_PROMPT',

    'ALL_PROMPTS',
    'PROMPT_METADATA',
    'get_all_prompts',
    'get_all_metadata',

    *_legacy_exports,
]


def get_all_prompts() -> dict:

    return get_loader().get_all_prompts()


def get_all_metadata() -> dict:

    return get_loader().get_all_metadata()


class _LazyDict:


    def __init__(self, loader_func):
        self._loader_func = loader_func
        self._cache = None

    def _load(self):
        if self._cache is None:
            self._cache = self._loader_func()
        return self._cache

    def __getitem__(self, key):
        return self._load()[key]

    def __contains__(self, key):
        return key in self._load()

    def __iter__(self):
        return iter(self._load())

    def __len__(self):
        return len(self._load())

    def keys(self):
        return self._load().keys()

    def values(self):
        return self._load().values()

    def items(self):
        return self._load().items()

    def get(self, key, default=None):
        return self._load().get(key, default)

    def __repr__(self):
        return repr(self._load())


ALL_PROMPTS = _LazyDict(get_all_prompts)
PROMPT_METADATA = _LazyDict(get_all_metadata)
