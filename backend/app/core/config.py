from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict

from app.core.paths import PROJECT_ROOT


class Settings(BaseSettings):
    app_name: str = "LLM Penetration Testing System"
    app_env: str = "development"
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    openai_api_key: str = ""
    openai_model: str = "gpt-5.4"
    openai_base_url: str = "https://88996api.cloud/v1"
    openai_wire_api: str = "chat_completions"
    llm_reasoning_effort: str = "low"

    model_config = SettingsConfigDict(
        env_file=str(PROJECT_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
