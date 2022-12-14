"""empty message

Revision ID: 584ae32791fa
Revises: 581222eab3d7
Create Date: 2022-11-01 14:34:45.373708

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '584ae32791fa'
down_revision = '581222eab3d7'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('post',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('title', sa.String(length=50), nullable=True),
    sa.Column('category', sa.String(length=50), nullable=True),
    sa.Column('description', sa.TEXT(), nullable=True),
    sa.Column('image', sa.String(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_post_id'), 'post', ['id'], unique=False)
    op.drop_index('ix_product_id', table_name='product')
    op.drop_table('product')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('product',
    sa.Column('id', sa.INTEGER(), nullable=False),
    sa.Column('title', sa.VARCHAR(length=50), nullable=True),
    sa.Column('price', sa.NUMERIC(precision=10, scale=2), nullable=True),
    sa.Column('category', sa.VARCHAR(length=50), nullable=True),
    sa.Column('description', sa.TEXT(), nullable=True),
    sa.Column('image', sa.VARCHAR(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_product_id', 'product', ['id'], unique=False)
    op.drop_index(op.f('ix_post_id'), table_name='post')
    op.drop_table('post')
    # ### end Alembic commands ###
