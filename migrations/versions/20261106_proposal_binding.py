"""change_proposals: the object ID is the hashed request's object (security review F5, 2026-10-31)

Revision ID: 20261106_proposal_binding
Revises: 20261105_change_proposals
Create Date: 2026-10-31

The page shows target_id as "the object the proposal is bound to", and the hash binds `request`. This
CHECK makes them the same thing: the stored request must be exactly the canonical disable request for
target_id (clw.broker.proposals.canonical_request), so no writer can store one user's ID beside a request
that disables another.
"""

from alembic import op

revision = "20261106_proposal_binding"
down_revision = "20261105_change_proposals"
branch_labels = None
depends_on = None

_CHECK = ("request = jsonb_build_object('method', 'PATCH', 'path', '/v1.0/users/' || target_id, "
          "'body', jsonb_build_object('accountEnabled', false))")


def upgrade() -> None:
    op.create_check_constraint("ck_change_proposals_request_is_target", "change_proposals", _CHECK)


def downgrade() -> None:
    op.drop_constraint("ck_change_proposals_request_is_target", "change_proposals", type_="check")
