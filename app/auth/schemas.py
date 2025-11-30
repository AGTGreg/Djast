"""
Write your schemas here. You can create Pydantic models using the built-in
`get_schema` method from your SQLAlchemy models.

Example (Assuming that `Item` inherits from `models.Model`):

from .models import Item

ItemCreate = Item.get_schema(exclude={"id"})
ItemRead = Item.get_schema()
"""
