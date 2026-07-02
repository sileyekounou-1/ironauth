"""schema initial : af_users + af_oauth_accounts

Revision ID: 0001_initial
Revises:
Create Date: 2026-07-02

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "af_users",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("hashed_password", sa.String(length=255), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("1")),
        sa.Column("is_verified", sa.Boolean(), nullable=False, server_default=sa.text("0")),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column("totp_secret", sa.String(length=64), nullable=True),
        sa.Column("totp_enabled", sa.Boolean(), nullable=False, server_default=sa.text("0")),
        sa.Column("email_verification_token", sa.String(length=64), nullable=True),
        sa.Column("email_verification_expires_at", sa.Float(), nullable=True),
        sa.Column("password_reset_token", sa.String(length=64), nullable=True),
        sa.Column("password_reset_expires_at", sa.Float(), nullable=True),
        sa.Column("sessions_valid_from", sa.Float(), nullable=True),
    )
    op.create_index("ix_af_users_email", "af_users", ["email"], unique=True)

    op.create_table(
        "af_oauth_accounts",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("provider", sa.String(length=50), nullable=False),
        sa.Column("provider_user_id", sa.String(length=255), nullable=False),
        sa.Column("access_token", sa.String(length=512), nullable=False),
        sa.Column("refresh_token", sa.String(length=512), nullable=True),
        sa.Column("expires_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_af_oauth_accounts_user_id", "af_oauth_accounts", ["user_id"])


def downgrade() -> None:
    op.drop_index("ix_af_oauth_accounts_user_id", table_name="af_oauth_accounts")
    op.drop_table("af_oauth_accounts")
    op.drop_index("ix_af_users_email", table_name="af_users")
    op.drop_table("af_users")
