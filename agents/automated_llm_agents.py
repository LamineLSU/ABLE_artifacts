
import os
import json
import time
import requests
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass
from abc import ABC, abstractmethod

@dataclass
class LLMConfig:

    provider: str = "ollama"
    model: str = "gpt-4"
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    temperature: float = 0.7
    max_tokens: int = 8000
    timeout: int = 240
    retry_count: int = 3

    def __post_init__(self):
        if self.provider == "openai" and not self.base_url:
            self.base_url = "https://api.openai.com/v1"
            if self.model == "gpt-4":
                self.model = "gpt-4"
            if self.temperature != 1.0 and self.model in ["gpt-5-nano", "o1-preview", "o1-mini"]:
                self.temperature = 1.0
        elif self.provider == "anthropic" and not self.base_url:
            self.base_url = "https://api.anthropic.com/v1"
            if self.model == "gpt-4":
                self.model = "claude-3-5-sonnet-20241022"
        elif self.provider == "ollama" and not self.base_url:
            self.base_url = "http://localhost:11434"
            if self.model == "gpt-4":
                self.model = "qwen2.5:latest"

class BaseLLMAgent(ABC):


    def __init__(self, config: LLMConfig = None):
        self.config = config or LLMConfig()

    @abstractmethod
    def call_llm(self, prompt: str) -> str:

        pass

    def is_available(self) -> bool:

        return True

class OpenAIAgent(BaseLLMAgent):


    DEBUG_MODE = False

    def __init__(self, config: LLMConfig = None):
        super().__init__(config)
        if not self.config.api_key:
            self.config.api_key = os.getenv('OPENAI_API_KEY')

    def call_llm(self, prompt: str) -> str:

        if not self.config.api_key:
            return "Error: OpenAI API key not provided. Set OPENAI_API_KEY environment variable."

        print(f"[*] Sending prompt to OpenAI {self.config.model}")
        print(f"[*] Prompt length: {len(prompt)} characters")

        if self.DEBUG_MODE:
            prompt_file = f"debug_openai_prompt_{int(time.time())}.txt"
            with open(prompt_file, 'w', encoding='utf-8') as f:
                f.write(f"OpenAI Model: {self.config.model}\n")
                f.write(f"Temperature: {self.config.temperature}\n")
                f.write(f"Max Tokens: {self.config.max_tokens}\n")
                f.write("="*80 + "\n")
                f.write(prompt)
            print(f"[DEBUG] Prompt saved to: {prompt_file}")

        headers = {
            "Authorization": f"Bearer {self.config.api_key}",
            "Content-Type": "application/json"
        }

        payload = {
            "model": self.config.model,
            "messages": [
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "max_completion_tokens": self.config.max_tokens
        }

        if self.config.temperature != 1.0:
            payload["temperature"] = self.config.temperature

        for attempt in range(self.config.retry_count):
            try:
                response = requests.post(
                    f"{self.config.base_url}/chat/completions",
                    headers=headers,
                    json=payload,
                    timeout=self.config.timeout
                )

                if response.status_code == 200:
                    result = response.json()
                    llm_response = result['choices'][0]['message']['content']

                    print(f"[*] Received response from OpenAI")
                    print(f"[*] Response length: {len(llm_response)} characters")

                    if self.DEBUG_MODE:
                        response_file = f"debug_openai_response_{int(time.time())}.txt"
                        with open(response_file, 'w', encoding='utf-8') as f:
                            f.write(f"OpenAI Model: {self.config.model}\n")
                            f.write(f"Response Length: {len(llm_response)} characters\n")
                            f.write("="*80 + "\n")
                            f.write(llm_response)
                        print(f"[DEBUG] Response saved to: {response_file}")

                    return llm_response
                else:
                    error_msg = f"OpenAI API Error {response.status_code}: {response.text}"
                    print(f"[!] Attempt {attempt + 1}: {error_msg}")

                    if attempt < self.config.retry_count - 1:
                        time.sleep(2 ** attempt)

            except Exception as e:
                print(f"[!] OpenAI call attempt {attempt + 1} failed: {e}")
                if attempt < self.config.retry_count - 1:
                    time.sleep(2 ** attempt)

        return f"Error: Failed to get response from OpenAI after {self.config.retry_count} attempts"

    def is_available(self) -> bool:

        if not self.config.api_key:
            return False

        try:
            test_response = self.call_llm("Test")
            return not test_response.startswith("Error:")
        except:
            return False

class AnthropicAgent(BaseLLMAgent):


    def __init__(self, config: LLMConfig = None):
        super().__init__(config)
        if not self.config.api_key:
            self.config.api_key = os.getenv('ANTHROPIC_API_KEY')

    def call_llm(self, prompt: str) -> str:

        if not self.config.api_key:
            return "Error: Anthropic API key not provided. Set ANTHROPIC_API_KEY environment variable."

        headers = {
            "x-api-key": self.config.api_key,
            "Content-Type": "application/json",
            "anthropic-version": "2023-06-01"
        }

        payload = {
            "model": self.config.model,
            "max_tokens": self.config.max_tokens,
            "temperature": self.config.temperature,
            "messages": [
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        }

        for attempt in range(self.config.retry_count):
            try:
                response = requests.post(
                    f"{self.config.base_url}/messages",
                    headers=headers,
                    json=payload,
                    timeout=self.config.timeout
                )

                if response.status_code == 200:
                    result = response.json()
                    return result['content'][0]['text']
                else:
                    error_msg = f"Anthropic API Error {response.status_code}: {response.text}"
                    print(f"[!] Attempt {attempt + 1}: {error_msg}")

                    if attempt < self.config.retry_count - 1:
                        time.sleep(2 ** attempt)

            except Exception as e:
                print(f"[!] Anthropic call attempt {attempt + 1} failed: {e}")
                if attempt < self.config.retry_count - 1:
                    time.sleep(2 ** attempt)

        return f"Error: Failed to get response from Anthropic after {self.config.retry_count} attempts"

    def is_available(self) -> bool:

        if not self.config.api_key:
            return False

        try:
            test_response = self.call_llm("Test")
            return not test_response.startswith("Error:")
        except:
            return False

class OllamaAgent(BaseLLMAgent):


    def call_llm(self, prompt: str) -> str:

        try:
            payload = {
                "model": self.config.model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": self.config.temperature,
                    "num_predict": self.config.max_tokens,
                    "top_p": 0.9
                }
            }

            response = requests.post(
                f"{self.config.base_url}/api/generate",
                json=payload,
                timeout=self.config.timeout
            )

            if response.status_code == 200:
                result = response.json()
                return result.get('response', '')
            else:
                return f"Error: Ollama HTTP {response.status_code}: {response.text}"

        except requests.exceptions.ConnectionError:
            return "Error: Cannot connect to Ollama. Make sure Ollama is running on localhost:11434"
        except requests.exceptions.Timeout:
            return f"Error: Ollama request timed out after {self.config.timeout}s"
        except Exception as e:
            return f"Error calling Ollama: {str(e)}"

    def is_available(self) -> bool:

        try:
            response = requests.get(f"{self.config.base_url}/api/tags", timeout=5)
            return response.status_code == 200
        except:
            return False

    def list_models(self) -> List[str]:

        try:
            response = requests.get(f"{self.config.base_url}/api/tags", timeout=10)
            if response.status_code == 200:
                models_data = response.json()
                return [model['name'] for model in models_data.get('models', [])]
        except:
            pass
        return []

class ManualGPT5Agent(BaseLLMAgent):


    def call_llm(self, prompt: str) -> str:

        print("\n" + "="*80)
        print("MANUAL LLM PROMPT (Copy to your preferred LLM)")
        print("="*80)

        prompt_file = "llm_prompt.txt"
        with open(prompt_file, 'w', encoding='utf-8') as f:
            f.write(prompt)

        print(f"Prompt saved to: {prompt_file}")
        print("Copy the prompt above and paste it into your LLM (GPT-4, Claude, etc.)")
        print("\nPaste the LLM response here:")

        response_lines = []
        print("(Press Enter twice when finished)")

        while True:
            try:
                line = input()
                if not line and len(response_lines) > 0 and not response_lines[-1]:
                    break
                response_lines.append(line)
            except EOFError:
                break

        response = "\n".join(response_lines).strip()

        response_file = "llm_response.txt"
        with open(response_file, 'w', encoding='utf-8') as f:
            f.write(response)
        print(f"Response saved to: {response_file}")

        return response

class SmartLLMOrchestrator:


    def __init__(self, preferred_providers: List[str] = None, configs: Dict[str, LLMConfig] = None):
        self.preferred_providers = preferred_providers or ["openai", "anthropic", "ollama", "manual"]
        self.configs = configs or {}
        self.current_agent = None
        self.current_provider = None

        self._select_best_agent()

    def _select_best_agent(self):

        print("[*] Detecting available LLM providers...")

        for provider in self.preferred_providers:
            config = self.configs.get(provider, LLMConfig(provider=provider))
            agent = self._create_agent(provider, config)

            print(f"[*] Testing {provider}...")

            if agent.is_available():
                self.current_agent = agent
                self.current_provider = provider
                print(f"[+] Selected LLM provider: {provider}")

                if provider == "ollama":
                    models = agent.list_models()
                    print(f"[+] Available Ollama models: {models}")

                return
            else:
                print(f"[!] {provider} not available")

        print("[!] No automatic LLM providers available, using manual mode")
        self.current_agent = ManualGPT5Agent()
        self.current_provider = "manual"

    def _create_agent(self, provider: str, config: LLMConfig) -> BaseLLMAgent:

        if provider == "openai":
            return OpenAIAgent(config)
        elif provider == "anthropic":
            return AnthropicAgent(config)
        elif provider == "ollama":
            return OllamaAgent(config)
        else:
            return ManualGPT5Agent(config)

    def call_llm(self, prompt: str, provider_preference: Optional[str] = None) -> str:

        if provider_preference and provider_preference != self.current_provider:
            config = self.configs.get(provider_preference, LLMConfig(provider=provider_preference))
            temp_agent = self._create_agent(provider_preference, config)

            if temp_agent.is_available():
                print(f"[*] Switching to {provider_preference} for this call")
                return temp_agent.call_llm(prompt)
            else:
                print(f"[!] {provider_preference} not available, using {self.current_provider}")

        print(f"[*] Using {self.current_provider} for analysis...")
        return self.current_agent.call_llm(prompt)

    def get_provider_info(self) -> Dict[str, Any]:

        info = {
            'current_provider': self.current_provider,
            'model': self.current_agent.config.model if self.current_agent else 'unknown',
            'available_providers': []
        }

        for provider in ["openai", "anthropic", "ollama", "manual"]:
            config = self.configs.get(provider, LLMConfig(provider=provider))
            agent = self._create_agent(provider, config)

            provider_info = {
                'name': provider,
                'available': agent.is_available(),
                'model': config.model
            }

            if provider == "ollama" and agent.is_available():
                provider_info['models'] = agent.list_models()

            info['available_providers'].append(provider_info)

        return info

    def switch_provider(self, provider: str, config: LLMConfig = None):

        if not config:
            config = self.configs.get(provider, LLMConfig(provider=provider))

        agent = self._create_agent(provider, config)
        if agent.is_available():
            self.current_agent = agent
            self.current_provider = provider
            self.configs[provider] = config
            print(f"[+] Switched to {provider}")
            return True
        else:
            print(f"[!] Cannot switch to {provider}: not available")
            return False

class AutomatedAgentFactory:


    @staticmethod
    def create_smart_orchestrator(preferred_providers: List[str] = None,
                                 api_keys: Dict[str, str] = None,
                                 models: Dict[str, str] = None) -> SmartLLMOrchestrator:


        if not preferred_providers:
            preferred_providers = ["openai", "anthropic", "ollama", "manual"]

        configs = {}

        openai_key = api_keys.get('openai') if api_keys else os.getenv('OPENAI_API_KEY')
        openai_model = models.get('openai', 'gpt-4') if models else 'gpt-4'
        configs['openai'] = LLMConfig(
            provider="openai",
            model=openai_model,
            api_key=openai_key,
            max_tokens=2000
        )

        anthropic_key = api_keys.get('anthropic') if api_keys else os.getenv('ANTHROPIC_API_KEY')
        anthropic_model = models.get('anthropic', 'claude-3-5-sonnet-20241022') if models else 'claude-3-5-sonnet-20241022'
        configs['anthropic'] = LLMConfig(
            provider="anthropic",
            model=anthropic_model,
            api_key=anthropic_key,
            max_tokens=8000
        )

        ollama_model = models.get('ollama', 'qwen2.5:latest') if models else 'qwen2.5:latest'
        configs['ollama'] = LLMConfig(
            provider="ollama",
            model=ollama_model,
            base_url="http://localhost:11434",
            max_tokens=8000
        )

        configs['manual'] = LLMConfig(
            provider="manual",
            model="manual_input"
        )

        return SmartLLMOrchestrator(preferred_providers, configs)

    @staticmethod
    def create_specific_agent(provider: str, **kwargs) -> BaseLLMAgent:

        config = LLMConfig(provider=provider, **kwargs)

        if provider == "openai":
            return OpenAIAgent(config)
        elif provider == "anthropic":
            return AnthropicAgent(config)
        elif provider == "ollama":
            return OllamaAgent(config)
        else:
            return ManualGPT5Agent(config)

def setup_environment_keys():

    keys = {}

    openai_key = os.getenv('OPENAI_API_KEY')
    anthropic_key = os.getenv('ANTHROPIC_API_KEY')

    if openai_key:
        keys['openai'] = openai_key
        print("[+] Found OpenAI API key in environment")

    if anthropic_key:
        keys['anthropic'] = anthropic_key
        print("[+] Found Anthropic API key in environment")

    if not keys:
        print("\n[*] No API keys found in environment variables")
        print("To use online LLMs, set environment variables:")
        print("  set OPENAI_API_KEY=your_openai_key")
        print("  set ANTHROPIC_API_KEY=your_anthropic_key")
        print("Or the pipeline will fallback to local Ollama or manual mode")

    return keys

def test_llm_providers():

    print("="*60)
    print("TESTING LLM PROVIDERS")
    print("="*60)

    orchestrator = AutomatedAgentFactory.create_smart_orchestrator()
    provider_info = orchestrator.get_provider_info()

    print(f"Current provider: {provider_info['current_provider']}")
    print(f"Current model: {provider_info['model']}")
    print("\nAll providers:")

    for provider in provider_info['available_providers']:
        status = "✅ Available" if provider['available'] else "❌ Not available"
        print(f"  {provider['name']}: {status} (model: {provider['model']})")

        if provider['name'] == 'ollama' and provider.get('models'):
            print(f"    Ollama models: {', '.join(provider['models'][:3])}")

    return orchestrator

if __name__ == "__main__":
    test_llm_providers()