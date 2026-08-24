from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = '0005_device_boot_status'
down_revision = '0004_activity_log'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('device_certificates', sa.Column('last_status_counter', sa.BigInteger(), nullable=False, server_default='0'))
    op.add_column('device_certificates', sa.Column('running_firmware_version', sa.String(64), nullable=False, server_default=''))
    op.add_column('device_certificates', sa.Column('last_status_at', sa.BigInteger(), nullable=False, server_default='0'))


def downgrade() -> None:
    op.drop_column('device_certificates', 'last_status_at')
    op.drop_column('device_certificates', 'running_firmware_version')
    op.drop_column('device_certificates', 'last_status_counter')
