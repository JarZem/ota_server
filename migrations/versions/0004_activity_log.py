from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = '0004_activity_log'
down_revision = '0003_ota_observability'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'ota_server_activity_log',
        sa.Column('id', sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column('created_at', sa.BigInteger(), nullable=False),
        sa.Column('category', sa.String(16), nullable=False),
        sa.Column('severity', sa.String(8), nullable=False, server_default='INFO'),
        sa.Column('device_id', sa.String(32)),
        sa.Column('action', sa.String(96), nullable=False),
        sa.Column('detail', sa.Text()),
    )
    op.create_index('ix_ota_activity_time', 'ota_server_activity_log', ['created_at', 'id'])
    op.create_index('ix_ota_activity_category', 'ota_server_activity_log', ['category', 'created_at'])
    op.create_index('ix_ota_activity_device', 'ota_server_activity_log', ['device_id', 'created_at'])


def downgrade() -> None:
    op.drop_index('ix_ota_activity_device', table_name='ota_server_activity_log')
    op.drop_index('ix_ota_activity_category', table_name='ota_server_activity_log')
    op.drop_index('ix_ota_activity_time', table_name='ota_server_activity_log')
    op.drop_table('ota_server_activity_log')
