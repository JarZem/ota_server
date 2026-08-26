from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = '0002_ota_check_session'
down_revision = '0001_mysql_initial'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        'ota_server_device_certificates',
        sa.Column('provision_counter', sa.BigInteger(), nullable=False, server_default='0'),
    )
    op.add_column(
        'ota_server_device_certificates',
        sa.Column('provision_random', sa.LargeBinary(8), nullable=True),
    )
    op.add_column(
        'ota_server_device_certificates',
        sa.Column('provision_context_updated_at', sa.BigInteger(), nullable=True),
    )

    op.create_table(
        'ota_server_download_grants',
        sa.Column('id', sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column('device_id', sa.String(32), nullable=False),
        sa.Column('code', sa.String(8), nullable=False),
        sa.Column('version', sa.String(64), nullable=False),
        sa.Column('sha256', sa.String(64), nullable=False),
        sa.Column('grant_random', sa.LargeBinary(8), nullable=False),
        sa.Column('token_hash', sa.String(64), nullable=False, unique=True),
        sa.Column('created_at', sa.BigInteger(), nullable=False),
        sa.Column('expires_at', sa.BigInteger(), nullable=False),
        sa.Column('consumed_at', sa.BigInteger(), nullable=True),
    )
    op.create_index(
        'ix_ota_download_grants_lookup',
        'ota_server_download_grants',
        ['device_id', 'code', 'sha256', 'expires_at', 'consumed_at'],
    )


def downgrade() -> None:
    op.drop_index('ix_ota_download_grants_lookup', table_name='ota_server_download_grants')
    op.drop_table('ota_server_download_grants')
    op.drop_column('ota_server_device_certificates', 'provision_context_updated_at')
    op.drop_column('ota_server_device_certificates', 'provision_random')
    op.drop_column('ota_server_device_certificates', 'provision_counter')
