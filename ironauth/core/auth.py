from typing import Optional

from ironauth.adapters.database.sqlalchemy import SQLAlchemyAdapter
from ironauth.adapters.frameworks.fastapi import FastAPIAdapter
from ironauth.core.config import ironauthConfig
from ironauth.core.password import PasswordManager
from ironauth.core.session import SessionManager
from ironauth.plugins.oauth import OAuthPlugin
from ironauth.plugins.two_factor import TwoFactorPlugin


class ironauth:
    def __init__(
        self,
        database: SQLAlchemyAdapter,
        config: dict,
        plugins: list = [],
        adapter: dict | None = None,
    ):
        # 1. Validation config
        self._config = ironauthConfig(**config)

        # 2. Core services
        self._db = database
        self._session = SessionManager(self._config)
        self._password = PasswordManager()

        # 3. Plugins
        self._oauth_plugin: Optional[OAuthPlugin] = None
        self._two_factor_plugin: Optional[TwoFactorPlugin] = None
        self._init_plugins(plugins)

        # 4. Framework adapter
        self._adapter = self._init_adapter(adapter)

    def _init_plugins(self, plugins: list):
        for plugin in plugins:
            if isinstance(plugin, OAuthPlugin):
                if not self._config.oauth:
                    raise ValueError(
                        "OAuth plugin activé mais 'oauth' absent de la config"
                    )
                plugin.init(self._db, self._session, self._config.oauth)
                self._oauth_plugin = plugin

    def _init_adapter(self, adapter: Optional[dict]) -> FastAPIAdapter:
        if adapter is None or adapter.get("type") == "fastapi":
            return FastAPIAdapter(
                config=self._config,
                db=self._db,
                session=self._session,
                password=self._password,
                oauth_plugin=self._oauth_plugin,
                two_factor_plugin=self._two_factor_plugin,  # ← ajouter
            )
        raise ValueError(f"Adapter non supporté : {adapter.get('type')}")

    # --- API publique ---

    @property
    def router(self):
        """Router FastAPI à monter sur l'application."""
        return self._adapter.router

    def current_user(self, required: bool = True):
        """Dépendance FastAPI pour protéger les routes."""
        return self._adapter.current_user(required=required)

    async def init(self):
        """Initialise la base de données (création des tables)."""
        await self._db.init()
