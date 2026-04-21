import json
from pathlib import Path
from typing import Any
import config

class ConfigManager:
    """Manages reading and writing user preferences to data/user_settings.json"""
    def __init__(self, settings_file: str | Path = "data/user_settings.json"):
        project_root = Path(__file__).resolve().parents[1]
        self.settings_file = project_root / settings_file
        self.settings = self._load()
        
        # Apply loaded settings to config.py right away
        for k, v in self.settings.items():
            if hasattr(config, k):
                setattr(config, k, v)

    def _load(self) -> dict:
        if self.settings_file.exists():
            try:
                with open(self.settings_file, "r") as f:
                    return json.load(f)
            except json.JSONDecodeError:
                pass
        return {}

    def _save(self) -> None:
        self.settings_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.settings_file, "w") as f:
            json.dump(self.settings, f, indent=4)

    def get(self, key: str, default: Any = None) -> Any:
        # Check settings dict first, then fallback to config module
        if key in self.settings:
            return self.settings[key]
        return getattr(config, key, default)

    def set(self, key: str, value: Any) -> None:
        self.settings[key] = value
        setattr(config, key, value)
        self._save()
