"""
Define your module-specific SQLAlchemy models here. Your models must inherit
from one of these base classes:

`models.Base`: You get:
    1. Auto-tablename dirived from class name and module name
    2. AsyncAttrs for awaitable attributes

 or

`models.Model`: Inherits from `models.Base` so it provide all the above plus:
    1. Integer Primary Key 'id'
    2. Django-style async Manager via `objects` attribute
    3. Pydantic schema generation via `get_schema` method
"""

from djast.db import models
from sqlalchemy.orm import Mapped, mapped_column


# Write your models here.
