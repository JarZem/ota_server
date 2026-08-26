from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = '0003_ota_observability'
down_revision = '0002_ota_check_session'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'ota_server_artifact_publications',
        sa.Column('id', sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column('firmware_version', sa.String(64), nullable=False),
        sa.Column('firmware_filename', sa.String(255), nullable=False),
        sa.Column('firmware_sha256', sa.String(64), nullable=False),
        sa.Column('firmware_size', sa.BigInteger(), nullable=False),
        sa.Column('converter_project', sa.String(128)),
        sa.Column('converter_filename', sa.String(255)),
        sa.Column('converter_sha256', sa.String(64)),
        sa.Column('publisher_device_id', sa.String(32), nullable=False),
        sa.Column('publisher_certificate_fingerprint', sa.String(64), nullable=False),
        sa.Column('bin_verified', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('mjs_verified', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('z2m_loaded', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('published_at', sa.BigInteger(), nullable=False),
        sa.Column('converter_published_at', sa.BigInteger()),
        sa.Column('last_error', sa.Text()),
        sa.UniqueConstraint('firmware_version', 'firmware_filename', name='uq_ota_artifact_version_file'),
    )
    op.create_index(
        'ix_ota_artifact_publications_version',
        'ota_server_artifact_publications',
        ['firmware_version', 'published_at'],
    )

    op.create_table(
        'ota_server_provisioning_attempts',
        sa.Column('id', sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column('device_id', sa.String(32), nullable=False),
        sa.Column('counter', sa.BigInteger(), nullable=False),
        sa.Column('state', sa.String(64), nullable=False),
        sa.Column('started_at', sa.BigInteger(), nullable=False),
        sa.Column('challenge_sent_at', sa.BigInteger()),
        sa.Column('response_verified_at', sa.BigInteger()),
        sa.Column('provisioning_sent_at', sa.BigInteger()),
        sa.Column('completed_at', sa.BigInteger()),
        sa.Column('updated_at', sa.BigInteger(), nullable=False),
        sa.Column('error', sa.Text()),
        sa.UniqueConstraint('device_id', 'counter', name='uq_ota_provisioning_device_counter'),
    )
    op.create_index(
        'ix_ota_provisioning_attempts_device',
        'ota_server_provisioning_attempts',
        ['device_id', 'started_at'],
    )

    op.create_table(
        'ota_server_device_firmware_status',
        sa.Column('device_id', sa.String(32), primary_key=True),
        sa.Column('firmware_sha256', sa.String(64), primary_key=True),
        sa.Column('firmware_filename', sa.String(255), nullable=False),
        sa.Column('firmware_version', sa.String(64), nullable=False),
        sa.Column('firmware_code', sa.String(8)),
        sa.Column('state', sa.String(64), nullable=False),
        sa.Column('check_created_at', sa.BigInteger()),
        sa.Column('check_sent_at', sa.BigInteger()),
        sa.Column('token_expires_at', sa.BigInteger()),
        sa.Column('download_started_at', sa.BigInteger()),
        sa.Column('download_finished_at', sa.BigInteger()),
        sa.Column('download_failed_at', sa.BigInteger()),
        sa.Column('grant_consumed_at', sa.BigInteger()),
        sa.Column('last_error', sa.Text()),
        sa.Column('updated_at', sa.BigInteger(), nullable=False),
    )
    op.create_index(
        'ix_ota_device_firmware_state',
        'ota_server_device_firmware_status',
        ['device_id', 'state', 'updated_at'],
    )


def downgrade() -> None:
    op.drop_index('ix_ota_device_firmware_state', table_name='ota_server_device_firmware_status')
    op.drop_table('ota_server_device_firmware_status')
    op.drop_index('ix_ota_provisioning_attempts_device', table_name='ota_server_provisioning_attempts')
    op.drop_table('ota_server_provisioning_attempts')
    op.drop_index('ix_ota_artifact_publications_version', table_name='ota_server_artifact_publications')
    op.drop_table('ota_server_artifact_publications')
