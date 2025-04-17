import logging
import os
import uuid

import pytest_asyncio

logger = logging.getLogger(__name__)

TEST_USER_ID = uuid.uuid4()


def pytest_configure(config):
    os.environ["JWT_SECRET_KEY"] = str(uuid.uuid4())

@pytest_asyncio.fixture
async def test_token():
    return TEST_USER_ID


@pytest_asyncio.fixture
async def test_jwt_secret_key():
    return os.environ["JWT_SECRET_KEY"]


@pytest_asyncio.fixture
async def test_jwt_algorithm() -> str:
    return "HS256"
