from typing import Optional

from ironauth.adapters.database.sqlalchemy import SQLAlchemyAdapter
from ironauth.adapters.frameworks.fastapi import FastAPIAdapter
from ironauth.core.config import ironauthConfig
from ironauth.core.email_manager import EmailManager
from ironauth.core.password import PasswordManager
from ironauth.core.session import SessionManager
from ironauth.core.token_blacklist import TokenBlacklist
from ironauth.plugins.email.base import EmailProvider
from ironauth.plugins.oauth import OAuthPlugin
from ironauth.plugins.rate_limit import RateLimiter
from ironauth.plugins.two_factor import TwoFactorPlugin


class ironauth:
    def __init__(
        self,
        database: SQLAlchemyAdapter,
        config: dict,
        plugins: list | None = None,
        adapter: dict | None = None,
    ):
        plugins = plugins if plugins is not None else []
        # 1. Validation config
        self._config = ironauthConfig(**config)

        # 2. Core services
        self._db = database
        self._blacklist = TokenBlacklist()
        self._session = SessionManager(self._config, blacklist=self._blacklist)
        self._password = PasswordManager()

        # 3. Plugins
        self._oauth_plugin: OAuthPlugin | None = None
        self._two_factor_plugin: TwoFactorPlugin | None = None
        self._rate_limiter: RateLimiter | None = None
        self._email_manager: EmailManager | None = None
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

            elif isinstance(plugin, TwoFactorPlugin):
                plugin.init(self._db)
                self._two_factor_plugin = plugin

            elif isinstance(plugin, RateLimiter):
                self._rate_limiter = plugin

            elif isinstance(plugin, EmailProvider):
                from ironauth.core.config import EmailConfig
                email_config = self._config.email or EmailConfig()
                self._email_manager = EmailManager(
                    db=self._db,
                    provider=plugin,
                    base_url=email_config.base_url,
                    app_name=email_config.app_name,
                    from_email=email_config.from_email,
                    from_name=email_config.from_name,
                )

    def _init_adapter(self, adapter: Optional[dict]) -> FastAPIAdapter:
        if adapter is None or adapter.get("type") == "fastapi":
            return FastAPIAdapter(
                config=self._config,
                db=self._db,
                session=self._session,
                password=self._password,
                oauth_plugin=self._oauth_plugin,
                two_factor_plugin=self._two_factor_plugin,
                rate_limiter=self._rate_limiter,
                email_manager=self._email_manager,
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
