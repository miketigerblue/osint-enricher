# enricher/config.py

from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    database_url: str
    openai_api_key: str
    chroma_db_path: str = "./chroma_db"
    enrich_interval: int = 3600  # seconds

    # Pydantic-Settings v2 way to load a .env file
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8"
    )

settings = Settings()
