from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = '0001_mysql_initial'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'ota_server_firmware_images',
        sa.Column('filename', sa.String(255), primary_key=True),
        sa.Column('ota_ecosystem', sa.String(128), nullable=False, server_default='JaroslavZemanESP'),
        sa.Column('sha256', sa.String(64), nullable=False),
        sa.Column('size', sa.BigInteger(), nullable=False),
        sa.Column('version', sa.String(64)),
        sa.Column('revision', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('device_family', sa.String(128), nullable=False, server_default='unknown'),
        sa.Column('device_model', sa.String(128), nullable=False, server_default='unknown'),
        sa.Column('product_role', sa.String(128), nullable=False, server_default='unknown'),
        sa.Column('product', sa.String(128), nullable=False, server_default='unknown'),
        sa.Column('hardware_revision', sa.String(128), nullable=False, server_default='unknown'),
        sa.Column('chip_family', sa.String(64), nullable=False, server_default='ESP32-C6'),
        sa.Column('flash_size', sa.String(32), nullable=False, server_default='16MB'),
        sa.Column('channel', sa.String(32), nullable=False, server_default='stable'),
        sa.Column('secure_version', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('active', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('first_seen', sa.BigInteger(), nullable=False),
        sa.Column('last_seen', sa.BigInteger(), nullable=False),
        sa.Column('changed_at', sa.BigInteger(), nullable=False),
    )
    op.create_table(
        'ota_server_firmware_alias',
        sa.Column('filename', sa.String(255), primary_key=True),
        sa.Column('code', sa.String(8), nullable=False, unique=True),
        sa.Column('created_at', sa.BigInteger(), nullable=False),
    )
    op.create_table(
        'ota_server_firmware_history',
        sa.Column('id', sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column('filename', sa.String(255), nullable=False),
        sa.Column('sha256', sa.String(64), nullable=False),
        sa.Column('size', sa.BigInteger(), nullable=False),
        sa.Column('version', sa.String(64)),
        sa.Column('revision', sa.Integer(), nullable=False),
        sa.Column('detected_at', sa.BigInteger(), nullable=False),
    )
    op.create_table(
        'ota_server_dispatch',
        sa.Column('id', sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column('ieee', sa.String(32), nullable=False),
        sa.Column('filename', sa.String(255), nullable=False),
        sa.Column('sha256', sa.String(64), nullable=False),
        sa.Column('revision', sa.Integer(), nullable=False),
        sa.Column('sent_at', sa.BigInteger(), nullable=False),
        sa.Column('success', sa.Boolean(), nullable=False),
        sa.Column('error', sa.Text()),
    )
    op.create_index('ix_ota_server_dispatch_ieee_file', 'ota_server_dispatch', ['ieee', 'filename', 'sent_at'])
    op.create_table(
        'ota_server_device_provisioning',
        sa.Column('device_id', sa.String(32), primary_key=True),
        sa.Column('wifi_ssid', sa.String(255), nullable=False),
        sa.Column('wifi_security', sa.String(32), nullable=False),
        sa.Column('wifi_channel', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('ota_host', sa.String(255), nullable=False),
        sa.Column('ota_port', sa.Integer(), nullable=False),
        sa.Column('firmware_filename', sa.String(255)),
        sa.Column('firmware_sha256', sa.String(64)),
        sa.Column('transport', sa.String(32)),
        sa.Column('status', sa.String(64), nullable=False),
        sa.Column('error', sa.Text()),
        sa.Column('updated_at', sa.BigInteger(), nullable=False),
    )
    op.create_table(
        'ota_server_devices',
        sa.Column('device_id', sa.String(32), primary_key=True),
        sa.Column('device_enc_public_key', sa.LargeBinary(128), nullable=False),
        sa.Column('device_key_id', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('device_public_key_fingerprint', sa.String(128)),
        sa.Column('zigbee_ieee', sa.String(32)),
        sa.Column('ota_ecosystem', sa.String(128), nullable=False, server_default='JaroslavZemanESP'),
        sa.Column('device_model', sa.String(128), nullable=False, server_default='unknown'),
        sa.Column('firmware_product', sa.String(128), nullable=False, server_default='unknown'),
        sa.Column('product_role', sa.String(128), nullable=False),
        sa.Column('hardware_revision', sa.String(128), nullable=False),
        sa.Column('chip_family', sa.String(64), nullable=False, server_default='ESP32-C6'),
        sa.Column('flash_size', sa.String(32)),
        sa.Column('firmware_version', sa.String(64)),
        sa.Column('firmware_channel', sa.String(32), nullable=False, server_default='stable'),
        sa.Column('enrollment_counter', sa.BigInteger(), nullable=False, server_default='0'),
        sa.Column('state', sa.String(64), nullable=False, server_default='DISCOVERED'),
        sa.Column('last_message_id', sa.String(128)),
        sa.Column('last_challenge', sa.String(256)),
        sa.Column('auth_failed_reason', sa.Text()),
        sa.Column('created_at', sa.BigInteger(), nullable=False),
        sa.Column('updated_at', sa.BigInteger(), nullable=False),
    )
    op.create_table(
        'ota_server_command_counters',
        sa.Column('scope', sa.String(128), primary_key=True),
        sa.Column('provision_counter', sa.BigInteger(), nullable=False, server_default='0'),
        sa.Column('ota_counter', sa.BigInteger(), nullable=False, server_default='0'),
        sa.Column('updated_at', sa.BigInteger(), nullable=False),
    )
    op.create_table(
        'ota_server_device_certificates',
        sa.Column('device_id', sa.String(32), primary_key=True),
        sa.Column('ecosystem', sa.String(128), nullable=False),
        sa.Column('device_group', sa.String(128), nullable=False),
        sa.Column('device_model', sa.String(128), nullable=False),
        sa.Column('product_role', sa.String(128), nullable=False),
        sa.Column('hardware_revision', sa.String(128), nullable=False),
        sa.Column('chip_family', sa.String(64), nullable=False),
        sa.Column('flash_size', sa.String(32), nullable=False),
        sa.Column('certificate_pem', sa.Text(), nullable=False),
        sa.Column('certificate_fingerprint', sa.String(64), nullable=False, unique=True),
        sa.Column('public_key_der', sa.LargeBinary(512), nullable=False),
        sa.Column('public_key_uncompressed', sa.LargeBinary(128), nullable=False),
        sa.Column('certificate_not_before', sa.BigInteger(), nullable=False),
        sa.Column('certificate_not_after', sa.BigInteger(), nullable=False),
        sa.Column('certificate_subject', sa.Text(), nullable=False),
        sa.Column('certificate_issuer', sa.Text(), nullable=False),
        sa.Column('last_hello_counter', sa.BigInteger(), nullable=False, server_default='0'),
        sa.Column('registered_at', sa.BigInteger(), nullable=False),
        sa.Column('updated_at', sa.BigInteger(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table('ota_server_device_certificates')
    op.drop_table('ota_server_command_counters')
    op.drop_table('ota_server_devices')
    op.drop_table('ota_server_device_provisioning')
    op.drop_index('ix_ota_server_dispatch_ieee_file', table_name='ota_server_dispatch')
    op.drop_table('ota_server_dispatch')
    op.drop_table('ota_server_firmware_history')
    op.drop_table('ota_server_firmware_alias')
    op.drop_table('ota_server_firmware_images')
