"""Initial schema

Revision ID: ad3fdafaaa21
Revises: 
Create Date: 2026-09-24 18:24:49.351944

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'ad3fdafaaa21'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Users
    op.create_table(
        'users',
        sa.Column('id', sa.Uuid(), primary_key=True),
        sa.Column('username', sa.String(), nullable=False, unique=True, index=True),
        sa.Column('email', sa.String(), nullable=False, unique=True, index=True),
        sa.Column('hashed_password', sa.String(), nullable=False),
        sa.Column('role', sa.String(), server_default='ANALYST'),
        sa.Column('is_active', sa.Boolean(), server_default='true'),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('now()')),
        sa.Column('last_login', sa.DateTime(), nullable=True),
    )
    # Cases
    op.create_table(
        'cases',
        sa.Column('id', sa.Uuid(), primary_key=True),
        sa.Column('title', sa.String(), nullable=False),
        sa.Column('description', sa.String(), nullable=True),
        sa.Column('status', sa.String(), server_default='OPEN'),
        sa.Column('assigned_to', sa.Uuid(), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('created_by', sa.Uuid(), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('now()')),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.text('now()')),
    )
    # Detection Rules
    op.create_table(
        'detection_rules',
        sa.Column('id', sa.Uuid(), primary_key=True),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('description', sa.String(), nullable=True),
        sa.Column('severity', sa.String(), nullable=False),
        sa.Column('logic', sa.JSON(), nullable=False),
        sa.Column('mitre_technique', sa.String(), nullable=True),
        sa.Column('is_active', sa.Boolean(), server_default='true'),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('now()')),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.text('now()')),
    )
    # Alerts
    op.create_table(
        'alerts',
        sa.Column('id', sa.Uuid(), primary_key=True),
        sa.Column('title', sa.String(), nullable=False),
        sa.Column('description', sa.String(), nullable=True),
        sa.Column('severity', sa.String(), server_default='LOW'),
        sa.Column('status', sa.String(), server_default='NEW'),
        sa.Column('risk_score', sa.Float(), server_default='0.0'),
        sa.Column('source_event_id', sa.Uuid(), nullable=True),
        sa.Column('rule_id', sa.Uuid(), sa.ForeignKey('detection_rules.id'), nullable=True),
        sa.Column('host', sa.String(), nullable=True),
        sa.Column('user', sa.String(), nullable=True),
        sa.Column('source_ip', sa.String(), nullable=True),
        sa.Column('mitre_technique', sa.String(), nullable=True),
        sa.Column('assigned_to', sa.Uuid(), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('case_id', sa.Uuid(), sa.ForeignKey('cases.id'), nullable=True),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('now()')),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.text('now()')),
    )
    # Normalized Events
    op.create_table(
        'normalized_events',
        sa.Column('id', sa.Uuid(), primary_key=True),
        sa.Column('timestamp', sa.DateTime(), nullable=False),
        sa.Column('event_type', sa.String(), nullable=False),
        sa.Column('source_ip', sa.String(), nullable=True),
        sa.Column('destination_ip', sa.String(), nullable=True),
        sa.Column('user', sa.String(), nullable=True),
        sa.Column('host', sa.String(), nullable=True),
        sa.Column('process_name', sa.String(), nullable=True),
        sa.Column('command_line', sa.String(), nullable=True),
        sa.Column('raw_data', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('now()')),
    )

def downgrade() -> None:
    op.drop_table('normalized_events')
    op.drop_table('alerts')
    op.drop_table('detection_rules')
    op.drop_table('cases')
    op.drop_table('users')
