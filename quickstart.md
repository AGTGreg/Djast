# Djast Quickstart

Build a simple blog API with Posts and Authors in 10 minutes.

---

## 1. Setup

```bash
git clone https://github.com/AGTGreg/FastAPIBoilerplate.git
cd FastAPIBoilerplate
docker compose up --build
```

API is live at `http://localhost:8000/api/v1`. Docs at `/docs`.

---

## 2. Create an App

Open another terminal and get the container's id:
```bash
docker ps
```

Create a new app:

```bash
docker exec -it <container_id> python manage.py startapp myapp
```

This creates:

```
myapp/
├── __init__.py
├── models.py      # SQLAlchemy models
├── schemas.py     # Pydantic schemas
├── views.py       # FastAPI routes
└── tests.py
```

---

## 3. Register the Router

Edit `djast/urls.py`:

```python
from fastapi import APIRouter

from myapp.views import router as myapp_router  # Add this

api_router = APIRouter()

api_router.include_router(myapp_router, prefix="/myapp", tags=["myapp"])  # Add this
```

---

## 4. Create Models

Edit `myapp/models.py`:

```python
from sqlalchemy import String, Text, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from djast.db import models


class Author(models.Model):
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)

    posts: Mapped[list["Post"]] = relationship(back_populates="author")

    def __repr__(self) -> str:
        return f"<Author {self.name}>"


class Post(models.Model):
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    content: Mapped[str | None] = mapped_column(Text, default=None)
    author_id: Mapped[int] = mapped_column(ForeignKey("myapp_author.id"), nullable=False)

    author: Mapped["Author"] = relationship(back_populates="posts")

    def __repr__(self) -> str:
        return f"<Post {self.title}>"
```

**Note:** Djast auto-generates table names as `{app}_{model}` (e.g., `myapp_author`, `myapp_post`). No `__tablename__` needed. It also adds an id field. You can override these if you want.

---

## 5. Run Migrations

```bash
python manage.py makemigrations
```

Makemigrations will initialize Alembic and database and create a migration file in `migrations/versions/`.
**Remeber to ALWAYS inspect the generated migrations before you run them.** Go to `migrations/versions/` and open the new migration file to inspect it.

Apply the migrations:
```bash
python manage.py migrate
```

### Rename Detection

Let's rename `content` to `body` in the `Post` table. In `myapp/models.py`:

```python
body: Mapped[str | None] = mapped_column(Text, default=None)  # was: content
```

Run migrations again:

```bash
python manage.py makemigrations
```

Djast detects the rename and asks:

```
Did you rename column 'content' to 'body' in table 'myapp_post'? [y/N]:
```

Type `y`. Makemigrations will edit the migration file to rename the column instead of droping it and loose data.

```bash
python manage.py migrate
```

---

## 6. Interactive Shell

```bash
python manage.py shell
```

Session and models are auto-imported. Create some data:

```python
# Create an author
author = await myapp.Author.objects(session).create(name="Jane", email="jane@example.com")
await session.commit()

# Create posts
post1 = await myapp.Post.objects(session).create(title="Hello World", body="My first post", author_id=author.id)
post2 = await myapp.Post.objects(session).create(title="Second Post", body="More content", author_id=author.id)
await session.commit()
```

### Query with Manager (Django-style)

```python
# Get all authors
await myapp.Author.objects(session).all()

# Get a single record by any field(s)
await myapp.Author.objects(session).get(id=1)
await myapp.Author.objects(session).get(email="jane@example.com")

# Filter (returns multiple records)
await myapp.Post.objects(session).filter(author_id=1)

# Count
await myapp.Post.objects(session).count()
```

### Ofcourse you can allways use SQLAlchemy queries

You're never locked in. Use raw SQLAlchemy anytime:

```python
from sqlalchemy import select

# Get all authors
result = await session.scalars(select(myapp.Author))
result.all()

# Get by primary key
author = await session.get(myapp.Author, 1)
```

Exit shell: `exit()` or Ctrl+D.

---

## 7. Create Schemas

Edit `myapp/schemas.py`:

```python
from .models import Author, Post

# Author schemas
AuthorCreate = Author.get_schema(exclude={"id"})
AuthorRead = Author.get_schema()
AuthorUpdate = Author.get_schema(exclude={"id"})

# Post schemas
PostCreate = Post.get_schema(exclude={"id"})
PostRead = Post.get_schema()
PostUpdate = Post.get_schema(exclude={"id", "author_id"})
```

`get_schema()` introspects your SQLAlchemy model and generates a Pydantic schema automatically. No duplication.

---

## 8. Create Views

Edit `myapp/views.py`:

```python
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from djast.database import get_async_session
from .models import Author, Post
from .schemas import (
    AuthorCreate, AuthorRead, AuthorUpdate,
    PostCreate, PostRead, PostUpdate
)

router = APIRouter()


# ─── Authors ─────────────────────────────────────────────────────────────────

@router.post("/authors", response_model=AuthorRead, status_code=status.HTTP_201_CREATED)
async def create_author(
    payload: AuthorCreate,
    session: AsyncSession = Depends(get_async_session)
):
    return await Author.objects(session).create(**payload.model_dump())


@router.get("/authors", response_model=list[AuthorRead])
async def list_authors(session: AsyncSession = Depends(get_async_session)):
    return await Author.objects(session).all()


@router.get("/authors/{author_id}", response_model=AuthorRead)
async def get_author(author_id: int, session: AsyncSession = Depends(get_async_session)):
    author = await Author.objects(session).get(id=author_id)
    if not author:
        raise HTTPException(status_code=404, detail="Author not found")
    return author


@router.patch("/authors/{author_id}", response_model=AuthorRead)
async def update_author(
    author_id: int,
    payload: AuthorUpdate,
    session: AsyncSession = Depends(get_async_session)
):
    author = await Author.objects(session).get(id=author_id)
    if not author:
        raise HTTPException(status_code=404, detail="Author not found")
    return await Author.objects(session).update(author, **payload.model_dump(exclude_unset=True))


@router.delete("/authors/{author_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_author(author_id: int, session: AsyncSession = Depends(get_async_session)):
    author = await Author.objects(session).get(id=author_id)
    if not author:
        raise HTTPException(status_code=404, detail="Author not found")
    await Author.objects(session).delete(author)


# ─── Posts ───────────────────────────────────────────────────────────────────

@router.post("/posts", response_model=PostRead, status_code=status.HTTP_201_CREATED)
async def create_post(
    payload: PostCreate,
    session: AsyncSession = Depends(get_async_session)
):
    # Verify author exists
    author = await Author.objects(session).get(id=payload.author_id)
    if not author:
        raise HTTPException(status_code=400, detail="Author not found")
    return await Post.objects(session).create(**payload.model_dump())


@router.get("/posts", response_model=list[PostRead])
async def list_posts(session: AsyncSession = Depends(get_async_session)):
    return await Post.objects(session).all()


@router.get("/posts/{post_id}", response_model=PostRead)
async def get_post(post_id: int, session: AsyncSession = Depends(get_async_session)):
    post = await Post.objects(session).get(id=post_id)
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    return post


@router.patch("/posts/{post_id}", response_model=PostRead)
async def update_post(
    post_id: int,
    payload: PostUpdate,
    session: AsyncSession = Depends(get_async_session)
):
    post = await Post.objects(session).get(id=post_id)
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    return await Post.objects(session).update(post, **payload.model_dump(exclude_unset=True))


@router.delete("/posts/{post_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_post(post_id: int, session: AsyncSession = Depends(get_async_session)):
    post = await Post.objects(session).get(id=post_id)
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    await Post.objects(session).delete(post)
```

---

## 9. Test It

The server auto-reloads. Open `http://localhost:8000/docs` and test your endpoints.

---

## Summary

| Command | What it does |
|---------|--------------|
| `python manage.py startapp <name>` | Create a new app |
| `python manage.py makemigrations` | Generate migrations |
| `python manage.py migrate` | Apply migrations |
| `python manage.py shell` | IPython shell |

**Key features:**
- `models.Model` gives you auto table names, `id` PK, `.objects()` manager, and `.get_schema()`
- Use `.objects(session)` for Django-style queries or raw SQLAlchemy—your choice
- `get_schema()` generates Pydantic models from SQLAlchemy models

That's it. Build something.
