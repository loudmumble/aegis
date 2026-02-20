from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class OllamaConfig:
    base_url: str = "http://localhost:11434"
    model: str = "aegis-v2"
    reasoning_model: str = "llama3.2:latest"
    temperature: float = 0.1
    timeout: int = 120
    max_tokens: int = 4096


@dataclass
class EmbeddedModelConfig:
    """Configuration for the embedded GGUF model (llama-cpp-python)."""

    model_path: str = ""  # auto-discovered if empty
    n_ctx: int = 2048  # context window size
    n_threads: int = 0  # 0 = auto-detect CPU count
    n_gpu_layers: int = 0  # 0 = CPU only, -1 = all layers on GPU
    verbose: bool = False


@dataclass
class HybridLLMConfig:
    """Configuration for the hybrid LLM backend (embedded + Ollama fallback)."""

    backend: str = "auto"  # "auto" | "embedded" | "ollama"
    embedded: EmbeddedModelConfig = field(default_factory=EmbeddedModelConfig)
    ollama: OllamaConfig = field(default_factory=OllamaConfig)


@dataclass
class CaptureConfig:
    interface: str = "any"
    bpf_filter: str = "tcp"
    snap_length: int = 96
    ring_buffer_size: int = 10000
    flow_timeout: float = 30.0
    pcap_dir: Path = field(default_factory=lambda: Path("./aegis-data/pcap"))


@dataclass
class CadenceConfig:
    # Inter-arrival time analysis
    min_packets_for_analysis: int = 20
    iat_bucket_ms: float = 5.0
    # Regularity thresholds
    human_jitter_threshold: float = 0.15
    agent_regularity_threshold: float = 0.85
    # ITT fingerprinting
    itt_window_size: int = 50
    itt_profiles_dir: Path = field(
        default_factory=lambda: Path("./aegis-data/profiles")
    )
    # Behavioral baseline
    baseline_window_seconds: float = 300.0
    anomaly_sensitivity: float = 2.0


@dataclass
class RulesConfig:
    rules_dir: Path = field(default_factory=lambda: Path("./aegis-data/rules"))
    builtin_enabled: bool = True


@dataclass
class AlertConfig:
    console_enabled: bool = True
    json_log_enabled: bool = True
    json_log_path: Path = field(
        default_factory=lambda: Path("./aegis-data/alerts.jsonl")
    )
    webhook_url: str = ""
    webhook_enabled: bool = False
    min_severity: str = "low"


@dataclass
class AegisConfig:
    ollama: OllamaConfig = field(default_factory=OllamaConfig)
    llm: HybridLLMConfig = field(default_factory=HybridLLMConfig)
    capture: CaptureConfig = field(default_factory=CaptureConfig)
    cadence: CadenceConfig = field(default_factory=CadenceConfig)
    rules: RulesConfig = field(default_factory=RulesConfig)
    alerts: AlertConfig = field(default_factory=AlertConfig)
    verbose: bool = False

    def __post_init__(self):
        self.llm.ollama = self.ollama

    @classmethod
    def from_file(cls, path: Path) -> "AegisConfig":
        if path.exists():
            with open(path) as f:
                data = yaml.safe_load(f) or {}
            config = cls()
            sections = ("ollama", "capture", "cadence", "rules", "alerts")
            for section_name in sections:
                if section_name in data:
                    section = getattr(config, section_name)
                    for k, v in data[section_name].items():
                        if hasattr(section, k):
                            current = getattr(section, k)
                            if isinstance(current, Path):
                                setattr(section, k, Path(v))
                            else:
                                setattr(section, k, v)
            if "embedded" in data:
                for k, v in data["embedded"].items():
                    setattr(config.llm.embedded, k, v)
            if "llm" in data:
                llm_data = data["llm"]
                if "backend" in llm_data:
                    config.llm.backend = llm_data["backend"]
                if "embedded" in llm_data:
                    for k, v in llm_data["embedded"].items():
                        setattr(config.llm.embedded, k, v)
                if "ollama" in llm_data:
                    for k, v in llm_data["ollama"].items():
                        setattr(config.ollama, k, v)
            if "verbose" in data:
                config.verbose = data["verbose"]
            config.llm.ollama = config.ollama
            return config
        return cls()

    def ensure_dirs(self) -> None:
        self.capture.pcap_dir.mkdir(parents=True, exist_ok=True)
        self.cadence.itt_profiles_dir.mkdir(parents=True, exist_ok=True)
        self.rules.rules_dir.mkdir(parents=True, exist_ok=True)
        if self.alerts.json_log_enabled:
            self.alerts.json_log_path.parent.mkdir(parents=True, exist_ok=True)
