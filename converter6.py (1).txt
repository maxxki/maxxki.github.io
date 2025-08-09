import asyncio
import logging
import re
import time
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Type, AsyncIterator, Tuple
from dataclasses import dataclass, field
from enum import Enum
import json
import os
import sys
import threading
import yaml
from collections import defaultdict
import weakref

# Hugging Face Imports
try:
    from transformers import T5ForConditionalGeneration, T5Tokenizer
    import torch
    HUGGINGFACE_AVAILABLE = True
except ImportError:
    HUGGINGFACE_AVAILABLE = False
    print("Warning: Hugging Face libraries 'transformers' and 'torch' are not installed. ML functionality will be disabled.")


# ============================================================================
# 0. LOGGING SETUP & UTILITIES
# ============================================================================

class SecretsFilter(logging.Filter):
    """
    Ein Logging-Filter, der vertrauliche Informationen wie API-Schlüssel
    oder Passwörter aus Log-Nachrichten entfernt.
    """
    SENSITIVE_PATTERNS = [
        r'(api_key|password|token|secret|auth)=[\w\-\.]+',
        r'Bearer\s+[\w\-\.]+',
        r'Basic\s+[\w\-\.=]+',
    ]
    
    def filter(self, record):
        message = str(record.msg)
        for pattern in self.SENSITIVE_PATTERNS:
            message = re.sub(pattern, r'\1=***', message, flags=re.IGNORECASE)
        record.msg = message
        return True

def setup_logging(log_level=logging.INFO):
    """Konfiguriert das Logging für die Anwendung mit einem SecretsFilter."""
    log_file_path = Path("maxxki_analysis.log")
    if log_file_path.exists():
        log_file_path.unlink()

    formatter = logging.Formatter(
        '{"time": "%(asctime)s", "level": "%(levelname)s", "module": "%(name)s", "message": "%(message)s"}'
    )

    file_handler = logging.FileHandler(log_file_path, encoding='utf-8')
    file_handler.setFormatter(formatter)
    file_handler.addFilter(SecretsFilter())

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    stream_handler.addFilter(SecretsFilter())

    logging.basicConfig(
        level=log_level,
        handlers=[file_handler, stream_handler]
    )
    logging.getLogger().info("Logging initialized with enhanced SecretsFilter.")


# ============================================================================
# 1. CORE TYPES AND INTERFACES
# ============================================================================

class StatementType(Enum):
    """Definiert die Typen von HLASM-Statements."""
    MACRO_CALL = "MACRO_CALL"
    CICS_EXEC = "CICS_EXEC"
    SQL_EXEC = "SQL_EXEC"
    IMS_EXEC = "IMS_EXEC"
    JCL_STATEMENT = "JCL_STATEMENT"
    DATA_DEFINITION = "DATA_DEFINITION"
    SYSTEM_VARIABLE = "SYSTEM_VARIABLE"
    UNKNOWN = "UNKNOWN"

class ConversionConfidence(Enum):
    """Konfidenz-Level des Konvertierungsergebnisses."""
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"

class RiskLevel(Enum):
    """Risikolevel für ML-basierte Konvertierungen."""
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

@dataclass(frozen=True)
class PluginMetadata:
    """Metadaten für ein Konvertierungs-Plugin."""
    name: str
    version: str
    description: str
    priority: int
    
    def __post_init__(self):
        if not isinstance(self.priority, int) or self.priority < 0:
            raise ValueError("Priority must be a non-negative integer")

@dataclass
class SourceLocation:
    """Repräsentiert die Position einer Anweisung in einer Quelldatei."""
    file_path: str
    line_number: int
    
    def __post_init__(self):
        if self.line_number < 1:
            raise ValueError("Line number must be >= 1")

@dataclass
class ConversionResult:
    """Stellt das Ergebnis einer Konvertierung dar."""
    original_statement: str
    converted_statement: str
    statement_type: StatementType
    confidence: ConversionConfidence
    plugin_name: Optional[str] = None
    comments: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    risk_level: RiskLevel = RiskLevel.NONE
    processing_time_ms: float = 0.0
    
    @property
    def is_successful(self) -> bool:
        return len(self.errors) == 0 and self.confidence != ConversionConfidence.UNKNOWN

@dataclass
class ConversionContext:
    """Repräsentiert den Kontext der aktuellen Konvertierung."""
    options: Dict[str, Any]
    macros: Dict[str, Any]
    location: Optional[SourceLocation] = None
    thread_id: str = field(default_factory=lambda: str(threading.current_thread().ident))

    def with_location(self, location: SourceLocation):
        return ConversionContext(
            options=self.options,
            macros=self.macros,
            location=location,
            thread_id=self.thread_id
        )


# ============================================================================
# 2. DEPENDENCY INJECTION / SERVICE REGISTRY
# ============================================================================

class ServiceRegistry:
    """Thread-safe service registry for dependency injection."""
    
    _services: Dict[str, Any] = {}
    _lock = threading.RLock()
    _instances = weakref.WeakValueDictionary()

    @classmethod
    def get(cls, service_name: str, factory=None) -> Any:
        """
        Gibt eine Service-Instanz zurück oder erstellt sie bei Bedarf.
        
        Args:
            service_name: Der Name des Services.
            factory: Eine Funktion zur Erstellung des Services, falls dieser noch nicht existiert.
        """
        with cls._lock:
            if service_name not in cls._services:
                if factory:
                    instance = factory()
                    cls.register(service_name, instance)
                    return instance
                else:
                    raise ValueError(f"Service '{service_name}' not found and no factory provided.")
            return cls._services[service_name]

    @classmethod
    def register(cls, service_name: str, instance: Any) -> None:
        """Registriert eine Instanz für einen Service-Namen."""
        with cls._lock:
            cls._services[service_name] = instance
            cls._instances[service_name] = instance

    @classmethod
    def clear(cls) -> None:
        """Löscht alle Services (hauptsächlich für Tests)."""
        with cls._lock:
            cls._services.clear()
            cls._instances.clear()
# Fortsetzung von Teil 1
# ============================================================================
# 3. CONFIGURATION MANAGEMENT
# ============================================================================

class ConfigurationError(Exception):
    """Eigene Exception für Konfigurationsfehler."""
    pass

class ConfigurationManager:
    """Thread-safe configuration manager with caching and validation."""
    
    def __init__(self, config_dir: Path):
        self._config_dir = config_dir
        self._cache = {}
        self._cache_lock = threading.RLock()
        self._logger = logging.getLogger(self.__class__.__name__)
        self._file_timestamps = {}

    def load_config(self, config_name: str) -> Dict[str, Any]:
        """Lädt die Konfiguration mit Caching und Änderungsdetektion."""
        file_path = self._config_dir / f"{config_name}.yaml"
        
        with self._cache_lock:
            if not file_path.exists():
                self._logger.warning(f"Config file not found: {file_path}. Using default config.")
                return self._get_default_config(config_name)
            
            current_mtime = file_path.stat().st_mtime
            
            if (config_name in self._cache and 
                config_name in self._file_timestamps and
                self._file_timestamps[config_name] >= current_mtime):
                return self._cache[config_name]
            
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    config = yaml.safe_load(f) or {}
                
                self._validate_config(config, config_name)
                
                self._cache[config_name] = config
                self._file_timestamps[config_name] = current_mtime
                
                self._logger.info(f"Loaded config from {file_path}")
                return config
                
            except Exception as e:
                self._logger.error(f"Error loading config {config_name}: {e}")
                raise ConfigurationError(f"Failed to load config '{config_name}'") from e

    def _get_default_config(self, config_name: str) -> Dict[str, Any]:
        """Gibt Standardkonfigurationen zurück."""
        defaults = {
            'macros': {
                'system': {
                    'TESTMAC': {
                        'description': 'Basic test macro',
                        'params': [],
                        'body': 'L R15,=',
                        'metadata': {'source': 'legacy', 'risk_level': 'low'}
                    }
                }
            },
            'patterns': {
                'patterns': {
                    'jcl_exec': r'^//\s*\w+\s+EXEC\s+',
                    'cics_exec': r'EXEC\s+CICS\s+',
                    'macro_call': r'^[A-Z][A-Z0-9_]*(?:\([^)]*\))?$'
                }
            }
        }
        return defaults.get(config_name, {})

    def _validate_config(self, config: Dict, config_name: str) -> None:
        """Validiert die Konfigurationsstruktur."""
        if config_name == 'macros':
            for group_name, macros in config.items():
                if isinstance(macros, dict):
                    for macro_name, macro_def in macros.items():
                        if isinstance(macro_def, dict):
                            required_fields = ['description', 'params', 'body']
                            for field in required_fields:
                                if field not in macro_def:
                                    raise ConfigurationError(
                                        f"Macro {macro_name} missing required field: {field}"
                                    )


# ============================================================================
# 4. PLUGIN SYSTEM
# ============================================================================

class ConverterPlugin(ABC):
    """Abstrakte Basisklasse für Konvertierungs-Plugins."""
    def __init__(self, pattern_engine):
        self._pattern_engine = pattern_engine
        self._logger = logging.getLogger(self.__class__.__name__)
        self._statistics = defaultdict(int)
        self._is_initialized = False

    @property
    @abstractmethod
    def metadata(self) -> PluginMetadata:
        """Gibt die Metadaten des Plugins zurück."""
        pass

    def initialize(self) -> None:
        """Initialisiert die Plugin-Ressourcen."""
        self._is_initialized = True
        self._logger.info(f"Plugin {self.metadata.name} initialized")

    @abstractmethod
    def can_handle(self, statement: str, context: ConversionContext) -> bool:
        """Gibt an, ob das Plugin eine Anweisung verarbeiten kann."""
        pass

    @abstractmethod
    def convert(self, statement: str, context: ConversionContext) -> ConversionResult:
        """Führt die Konvertierung durch."""
        pass
    
    def get_statistics(self) -> Dict[str, int]:
        """Gibt die Nutzungsstatistik des Plugins zurück."""
        return dict(self._statistics)
    
    def reset_statistics(self) -> None:
        """Setzt die Plugin-Statistik zurück."""
        self._statistics.clear()


# ============================================================================
# 5. PLUGIN IMPLEMENTATIONS
# ============================================================================

class HybridPatternEngine:
    """Optimierte Pattern-Engine mit kompilierten Regex-Patterns."""
    
    def __init__(self, patterns_config: Dict[str, Any]):
        self._patterns = patterns_config.get('patterns', {})
        self._compiled_patterns = {}
        self._cache_lock = threading.RLock()
        self._compile_all_patterns()

    def _compile_all_patterns(self):
        """Kompiliert alle Patterns für bessere Performance."""
        for pattern_name, regex_str in self._patterns.items():
            try:
                self._compiled_patterns[pattern_name] = re.compile(regex_str, re.IGNORECASE)
            except re.error as e:
                logging.getLogger(self.__class__.__name__).error(
                    f"Invalid regex pattern '{pattern_name}': {e}"
                )

    def find_match(self, statement: str, pattern_name: str) -> Optional[re.Match]:
        """Sucht nach einem Pattern-Match."""
        with self._cache_lock:
            if pattern_name in self._compiled_patterns:
                return self._compiled_patterns[pattern_name].match(statement)
        return None

    def find_all_matches(self, statement: str, pattern_name: str) -> List[re.Match]:
        """Sucht nach allen Matches für ein Pattern."""
        with self._cache_lock:
            if pattern_name in self._compiled_patterns:
                return list(self._compiled_patterns[pattern_name].finditer(statement))
        return []

class UltimateMacroExpansionPlugin(ConverterPlugin):
    """
    Plugin zur Expansion von HLASM-Makros.
    Lädt Makro-Definitionen über den ServiceRegistry.
    """
    def __init__(self, pattern_engine):
        super().__init__(pattern_engine)
        self._macros = {}
        self.initialize()
        
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="UltimateMacroExpansionPlugin",
            version="2.0.0",
            description="Performs recursive macro expansion based on definitions from a shared config.",
            priority=100
        )
        
    def initialize(self) -> None:
        super().initialize()
        try:
            config_manager = ServiceRegistry.get('config_manager')
            config = config_manager.load_config('macros')
            self._macros = {k.upper(): v for k, v in config.items()}
            self._logger.info(f"Loaded {len(self._macros)} macro groups from config.")
        except Exception as e:
            self._logger.error(f"Failed to load macros: {e}")
            raise

    def can_handle(self, statement: str, context: ConversionContext) -> bool:
        parts = statement.strip().split(maxsplit=1)
        if not parts:
            return False
        macro_name = parts[0].upper()
        return macro_name in self._macros

    def convert(self, statement: str, context: ConversionContext) -> ConversionResult:
        self._statistics['handled_macros'] += 1
        macro_name, params_str = self._parse_macro_call(statement)
        macro_def = self._macros.get(macro_name.upper())

        if not macro_def:
            return ConversionResult(
                original_statement=statement,
                converted_statement=f"Unbekanntes Makro: {macro_name}",
                statement_type=StatementType.MACRO_CALL,
                confidence=ConversionConfidence.LOW,
                errors=[f"Macro '{macro_name}' not defined in macros.yaml."],
                plugin_name=self.metadata.name
            )

        expanded_body = self._expand_body(macro_def.get('body', []), params_str, context)
        
        return ConversionResult(
            original_statement=statement,
            converted_statement="\n".join(expanded_body),
            statement_type=StatementType.MACRO_CALL,
            confidence=ConversionConfidence.HIGH,
            plugin_name=self.metadata.name
        )

    def _parse_macro_call(self, statement: str) -> Tuple[str, str]:
        parts = statement.strip().split(maxsplit=1)
        macro_name = parts[0]
        params_str = parts[1] if len(parts) > 1 else ""
        return macro_name, params_str

    def _expand_body(self, body: List[str], params_str: str, context: ConversionContext) -> List[str]:
        expanded = []
        params = [p.strip() for p in params_str.split(',') if p.strip()]
        for line in body:
            line = re.sub(r'\{(\d+)\}', lambda m: params[int(m.group(1)) - 1] if int(m.group(1)) <= len(params) else '', line)
            line = line.replace('&SYSDATE', time.strftime("%Y-%m-%d"))
            expanded.append(line)
        return expanded


class CICSConversionPlugin(ConverterPlugin):
    """Plugin zur Konvertierung von EXEC CICS-Anweisungen."""
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="CICSConversionPlugin",
            version="1.1.0",
            description="Converts EXEC CICS statements.",
            priority=90
        )
    
    def can_handle(self, statement: str, context: ConversionContext) -> bool:
        return 'EXEC CICS' in statement.upper()

    def convert(self, statement: str, context: ConversionContext) -> ConversionResult:
        self._statistics['handled_cics'] += 1
        converted = f"// Konvertierter CICS-Befehl: {statement.strip()}"
        
        return ConversionResult(
            original_statement=statement,
            converted_statement=converted,
            statement_type=StatementType.CICS_EXEC,
            confidence=ConversionConfidence.HIGH,
            plugin_name=self.metadata.name
        )


class SQLConversionPlugin(ConverterPlugin):
    """Plugin zur Konvertierung von EXEC SQL-Anweisungen."""
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="SQLConversionPlugin",
            version="1.1.0",
            description="Converts EXEC SQL statements.",
            priority=85
        )
    
    def can_handle(self, statement: str, context: ConversionContext) -> bool:
        return 'EXEC SQL' in statement.upper()

    def convert(self, statement: str, context: ConversionContext) -> ConversionResult:
        self._statistics['handled_sql'] += 1
        converted = f"// Konvertierter SQL-Befehl: {statement.strip()}"

        return ConversionResult(
            original_statement=statement,
            converted_statement=converted,
            statement_type=StatementType.SQL_EXEC,
            confidence=ConversionConfidence.HIGH,
            plugin_name=self.metadata.name
        )

class IMSConversionPlugin(ConverterPlugin):
    """Plugin zur Konvertierung von IMS-Anweisungen (z.B. DL/I-Aufrufe)."""
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="IMSConversionPlugin",
            version="1.1.0",
            description="Converts IMS/DL1 statements.",
            priority=80
        )
    
    def can_handle(self, statement: str, context: ConversionContext) -> bool:
        return 'CBLTDLI' in statement.upper() or 'AIBTDLI' in statement.upper()

    def convert(self, statement: str, context: ConversionContext) -> ConversionResult:
        self._statistics['handled_ims'] += 1
        converted = f"// Konvertierter IMS-Befehl: {statement.strip()}"
        
        return ConversionResult(
            original_statement=statement,
            converted_statement=converted,
            statement_type=StatementType.IMS_EXEC,
            confidence=ConversionConfidence.HIGH,
            plugin_name=self.metadata.name
        )

class MLConversionPlugin(ConverterPlugin):
    """
    Plugin, das die ML-Engine für die Konvertierung verwendet.
    Dient als allgemeiner Fallback, wenn kein spezifisches Plugin zutrifft.
    """
    def __init__(self, pattern_engine):
        super().__init__(pattern_engine)
        self._ml_engine = self._initialize_ml_engine()
    
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="MLConversionPlugin",
            version="1.0.0",
            description="Uses a CodeT5 model for general HLASM-to-Python conversion.",
            priority=40
        )

    def _initialize_ml_engine(self):
        """Private Methode zur Initialisierung der ML-Engine."""
        if not HUGGINGFACE_AVAILABLE:
            self._logger.warning("Hugging Face libraries not available. ML functionality will be disabled.")
            return None
        
        try:
            ml_engine = CodeT5OptimizationEngine()
            if ml_engine.initialize():
                self._logger.info("ML engine successfully initialized.")
                return ml_engine
            else:
                self._logger.error("Failed to initialize ML engine. ML plugin will be inactive.")
                return None
        except Exception as e:
            self._logger.error(f"Error initializing ML engine: {e}")
            return None
    
    def can_handle(self, statement: str, context: ConversionContext) -> bool:
        """
        Dieses Plugin ist ein Fallback und kann grundsätzlich jede Anweisung verarbeiten,
        solange die ML-Engine initialisiert ist.
        """
        return self._ml_engine is not None

    def convert(self, statement: str, context: ConversionContext) -> ConversionResult:
        """
        Konvertiert die Anweisung mit der ML-Engine.
        """
        self._statistics['handled_ml_statements'] += 1
        return self._ml_engine.convert(statement)

class HLASMConversionPlugin(ConverterPlugin):
    """
    Konvertiert gängige HLASM-Anweisungen wie JCL.
    """
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="HLASMConversionPlugin",
            version="1.1.0",
            description="Converts standard HLASM and JCL instructions.",
            priority=10
        )
    
    def can_handle(self, statement: str, context: ConversionContext) -> bool:
        return self._pattern_engine.find_match(statement, 'jcl_exec') is not None

    def convert(self, statement: str, context: ConversionContext) -> ConversionResult:
        self._statistics['handled_statements'] += 1
        
        converted = f"# JCL EXEC statement: {statement.strip()}"
        statement_type = StatementType.JCL_STATEMENT
            
        return ConversionResult(
            original_statement=statement,
            converted_statement=converted,
            statement_type=statement_type,
            confidence=ConversionConfidence.MEDIUM,
            plugin_name=self.metadata.name
        )
# Fortsetzung von Teil 2
# ============================================================================
# 6. ML-ENGINE IMPLEMENTATION (Jetzt eigenständig)
# ============================================================================

class CodeT5OptimizationEngine:
    """
    Produktionsreife ML-Komponente mit verbesserter Fehlerbehandlung und Caching.
    Diese Klasse dient nun als Back-End für das MLConversionPlugin.
    """
    def __init__(self, model_name: str = "Salesforce/codet5-base"):
        self._logger = logging.getLogger(self.__class__.__name__)
        self._model = None
        self._tokenizer = None
        self._model_name = model_name
        self._device = "cuda" if torch.cuda.is_available() else "cpu" if HUGGINGFACE_AVAILABLE else None
        self._max_length = 512
        self._cache = {}
        self._cache_lock = threading.RLock()

    def initialize(self):
        """Initialisiert das ML-Modell mit umfassender Fehlerbehandlung."""
        if not HUGGINGFACE_AVAILABLE:
            self._logger.error("Hugging Face libraries are not available. Cannot initialize ML Engine.")
            return False

        try:
            self._logger.info(f"Loading CodeT5 model: {self._model_name}")
            self._tokenizer = T5Tokenizer.from_pretrained(self._model_name)
            self._model = T5ForConditionalGeneration.from_pretrained(self._model_name)
            
            if self._device and self._device != "cpu":
                self._model.to(self._device)
                
            self._model.eval()
            self._logger.info(f"Successfully loaded CodeT5 model on device: {self._device}")
            return True
            
        except Exception as e:
            self._logger.error(f"Failed to load CodeT5 model '{self._model_name}': {e}")
            self._model = None
            self._tokenizer = None
            return False
    
    def convert(self, statement: str) -> ConversionResult:
        """Konvertiert eine Anweisung mit ML mit Caching und Risikobewertung."""
        if not self._model or not self._tokenizer:
            return ConversionResult(
                original_statement=statement,
                converted_statement=f"# TODO: ML conversion for '{statement}' (model not loaded)",
                statement_type=StatementType.UNKNOWN,
                confidence=ConversionConfidence.UNKNOWN,
                risk_level=RiskLevel.HIGH,
                errors=["ML engine not initialized or failed to load."],
                plugin_name="ML_CODET5_ENGINE"
            )

        cache_key = hash(statement)
        with self._cache_lock:
            if cache_key in self._cache:
                cached_result = self._cache[cache_key]
                return ConversionResult(
                    original_statement=statement,
                    converted_statement=cached_result['converted'],
                    statement_type=StatementType.UNKNOWN,
                    confidence=ConversionConfidence.MEDIUM,
                    risk_level=cached_result['risk_level'],
                    comments=["Result from ML cache"],
                    plugin_name="ML_CODET5_ENGINE"
                )

        start_time = time.time()
        
        try:
            prefix = "Translate HLASM assembly to Python: "
            input_text = prefix + statement
            
            inputs = self._tokenizer(
                input_text, 
                return_tensors="pt", 
                max_length=self._max_length,
                truncation=True,
                padding=True
            )
            
            if self._device and self._device != "cpu":
                inputs = {k: v.to(self._device) for k, v in inputs.items()}
            
            with torch.no_grad():
                outputs = self._model.generate(
                    **inputs,
                    max_length=256,
                    num_beams=3,
                    temperature=0.7,
                    do_sample=True,
                    pad_token_id=self._tokenizer.pad_token_id,
                    eos_token_id=self._tokenizer.eos_token_id
                )
            
            converted_code = self._tokenizer.decode(outputs[0], skip_special_tokens=True)
            
            if converted_code.startswith(prefix):
                converted_code = converted_code[len(prefix):].strip()
            
            processing_time = (time.time() - start_time) * 1000
            
            confidence = self._assess_conversion_confidence(statement, converted_code)
            risk_level = self._assess_risk_level(statement, converted_code)
            
            with self._cache_lock:
                self._cache[cache_key] = {
                    'converted': converted_code,
                    'timestamp': time.time(),
                    'risk_level': risk_level
                }
            
            return ConversionResult(
                original_statement=statement,
                converted_statement=converted_code,
                statement_type=StatementType.UNKNOWN,
                confidence=confidence,
                risk_level=risk_level,
                comments=[f"ML conversion completed in {processing_time:.2f}ms"],
                processing_time_ms=processing_time,
                plugin_name="ML_CODET5_ENGINE"
            )
            
        except Exception as e:
            self._logger.error(f"ML conversion failed for statement '{statement}': {e}")
            processing_time = (time.time() - start_time) * 1000
            
            return ConversionResult(
                original_statement=statement,
                converted_statement=f"# ML conversion failed: {str(e)}",
                statement_type=StatementType.UNKNOWN,
                confidence=ConversionConfidence.UNKNOWN,
                risk_level=RiskLevel.HIGH,
                errors=[f"ML processing error: {str(e)}"],
                processing_time_ms=processing_time,
                plugin_name="ML_CODET5_ENGINE"
            )

    def _assess_conversion_confidence(self, original: str, converted: str) -> ConversionConfidence:
        """Bewertet die Konfidenz basierend auf der Qualität des Ergebnisses."""
        if not converted or converted.strip() == "":
            return ConversionConfidence.UNKNOWN
        if len(converted) < len(original) * 0.3:
            return ConversionConfidence.LOW
        elif "TODO" in converted or "FIXME" in converted:
            return ConversionConfidence.LOW
        elif converted.count('\n') > 1:
            return ConversionConfidence.MEDIUM
        else:
            return ConversionConfidence.MEDIUM

    def _assess_risk_level(self, original: str, converted: str) -> RiskLevel:
        """Bewertet das Risikolevel der Konvertierung."""
        high_risk_indicators = ["exec", "system", "os.", "subprocess", "eval"]
        medium_risk_indicators = ["import", "open", "file"]

        converted_lower = converted.lower()

        if any(indicator in converted_lower for indicator in high_risk_indicators):
            return RiskLevel.HIGH
        
        if any(indicator in converted_lower for indicator in medium_risk_indicators):
            return RiskLevel.MEDIUM
        
        return RiskLevel.LOW if converted.strip() else RiskLevel.NONE


# ============================================================================
# 7. MAIN ORCHESTRATOR
# ============================================================================

class MaxkiConverter:
    """
    Zentrale Klasse für die Konvertierung, die alle Plugins orchestriert.
    """
    def __init__(self, config_dir: Path):
        self._config_dir = config_dir
        self._logger = logging.getLogger(self.__class__.__name__)
        self._plugins: List[ConverterPlugin] = []
        
        # Registrierung des ConfigurationManagers im ServiceRegistry
        config_manager = ConfigurationManager(config_dir)
        ServiceRegistry.register('config_manager', config_manager)
        
        self._pattern_engine = HybridPatternEngine(config_manager.load_config('patterns'))
        self._initialize_plugins()

    def _initialize_plugins(self):
        """Initialisiert und registriert alle verfügbaren Plugins."""
        self._plugins.append(UltimateMacroExpansionPlugin(self._pattern_engine))
        self._plugins.append(CICSConversionPlugin(self._pattern_engine))
        self._plugins.append(SQLConversionPlugin(self._pattern_engine))
        self._plugins.append(IMSConversionPlugin(self._pattern_engine))
        
        # ML-Engine ist jetzt ein Plugin, das als Fallback dient
        self._plugins.append(MLConversionPlugin(self._pattern_engine))
        
        self._plugins.append(HLASMConversionPlugin(self._pattern_engine))

        # Sortiere Plugins nach Priorität (höhere Zahl zuerst)
        self._plugins.sort(key=lambda p: p.metadata.priority, reverse=True)
        self._logger.info(f"Initialized {len(self._plugins)} plugins, sorted by priority.")

    def convert_statement(self, statement: str, context: ConversionContext) -> ConversionResult:
        """Konvertiert eine einzelne Anweisung."""
        for plugin in self._plugins:
            start_time = time.time()
            if plugin.can_handle(statement, context):
                result = plugin.convert(statement, context)
                result.processing_time_ms = (time.time() - start_time) * 1000
                self._logger.info(f"Statement handled by plugin '{plugin.metadata.name}'.")
                return result
        
        self._logger.warning(f"No plugin could handle statement: {statement}")
        return ConversionResult(
            original_statement=statement,
            converted_statement=f"// No plugin found to convert this statement.",
            statement_type=StatementType.UNKNOWN,
            confidence=ConversionConfidence.UNKNOWN,
            errors=["No matching plugin found."],
            plugin_name="ORCHESTRATOR"
        )

    async def convert_file(self, file_path: Path, options: Dict[str, Any]) -> AsyncIterator[ConversionResult]:
        """Konvertiert eine ganze Datei asynchron."""
        self._logger.info(f"Starting async conversion for file: {file_path}")
        with open(file_path, 'r', encoding='utf-8') as f:
            for i, line in enumerate(f.readlines()):
                context = ConversionContext(options=options, macros={}, location=SourceLocation(str(file_path), i + 1))
                yield self.convert_statement(line.strip(), context)
        self._logger.info(f"Finished async conversion for file: {file_path}")
