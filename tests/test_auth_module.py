import datetime
import logging
import uuid

import jwt
import pytest
from fastapi import HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials

from auth_lib.auth import get_current_user_id

logger = logging.getLogger(__name__)


@pytest.mark.asyncio
async def test_valid_token(test_jwt_secret_key: str, test_jwt_algorithm: str):
    """
    Check if function does not work without JWT token
    """
    # given...
    user_id = uuid.uuid4()
    payload = {
        "sub": str(user_id),
    }
    token = jwt.encode(
        payload=payload,
        key=test_jwt_secret_key,
        algorithm=test_jwt_algorithm,
    )
    credentials = HTTPAuthorizationCredentials(credentials=token, scheme="Bearer")

    # when...
    result = await get_current_user_id(credentials)

    # then...
    assert result == user_id


@pytest.mark.asyncio
async def test_token_missing_sub(test_jwt_secret_key: str, test_jwt_algorithm: str):
    """
    Check if function does not work with missing 'sub'
    """
    # given...
    payload = {
        "sub": "",
    }
    token = jwt.encode(payload=payload, key=test_jwt_secret_key, algorithm=test_jwt_algorithm)
    credentials = HTTPAuthorizationCredentials(credentials=token, scheme="Bearer")

    # when...
    with pytest.raises(HTTPException) as exc_info:
        await get_current_user_id(credentials)

    # then...
    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert exc_info.value.detail == "Could not validate credentials"
    assert exc_info.value.headers == {"WWW-Authenticate": "Bearer"}


@pytest.mark.asyncio
async def test_expired_token(test_jwt_secret_key: str, test_jwt_algorithm: str):
    """
    Check if function does not work with expired token
    """
    # given...
    payload = {
        "sub": str(uuid.uuid4()),
        "exp": datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=2),
    }
    token = jwt.encode(payload=payload, key=test_jwt_secret_key, algorithm=test_jwt_algorithm)
    credentials = HTTPAuthorizationCredentials(credentials=token, scheme="Bearer")

    # when...
    with pytest.raises(HTTPException) as exc_info:
        await get_current_user_id(credentials)

    # then...
    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert exc_info.value.detail == "Token has expired"


@pytest.mark.asyncio
async def test_invalid_signature(test_jwt_algorithm: str):
    """
    Check if function does not work with invalid signature
    """
    # given...
    user_id = uuid.uuid4()
    token = jwt.encode(
        payload={"sub": str(user_id)}, key="wrong_secret", algorithm=test_jwt_algorithm
    )
    credentials = HTTPAuthorizationCredentials(credentials=token, scheme="Bearer")

    # when...
    with pytest.raises(HTTPException) as exc_info:
        await get_current_user_id(credentials)

    # then...
    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.asyncio
async def test_invalid_algorithm(
    test_jwt_secret_key: str,
):
    """
    Check if function does not work with invalid algorithm
    """
    # given...
    user_id = uuid.uuid4()
    token = jwt.encode(payload={"sub": str(user_id)}, key=test_jwt_secret_key, algorithm="HS512")
    credentials = HTTPAuthorizationCredentials(credentials=token, scheme="Bearer")

    # when...
    with pytest.raises(HTTPException) as exc_info:
        await get_current_user_id(credentials)

    # then...
    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
