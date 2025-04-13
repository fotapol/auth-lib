import uuid

from sqlmodel import SQLModel


class TokenData(SQLModel):
    user_id: uuid.UUID
