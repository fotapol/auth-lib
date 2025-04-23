import logging
import os
import uuid
from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

logger = logging.getLogger(__name__)

bearer_scheme = HTTPBearer()

JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY")
if not JWT_SECRET_KEY:
    logger.warning("JWT_SECRET_KEY does not set!")
    raise RuntimeError("JWT_SECRET_KEY must be set")

JWT_ALGORITHM = "HS256"


async def get_current_user_id(
    token: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> uuid.UUID:
    """
    Dependency to verify JWT token locally via SECRET_KEY and return user ID
    """
    if not JWT_SECRET_KEY:
        logger.error("JWT Secret Key is not configured for the library.")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Authentication setup error."
        )

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    auth_token = token.credentials

    try:
        payload = jwt.decode(
            auth_token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM], options={"verify_aud": False},
        )
        user_id_str: str | None = payload.get("sub")
        if user_id_str is None:
            logger.error("Token payload missing 'sub' (user ID) field")
            raise credentials_exception

        logger.debug(f"Token validated locally for user_id: {user_id_str}")
        return uuid.UUID(user_id_str)

    except jwt.ExpiredSignatureError:
        logger.debug("Token has expired")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.MissingRequiredClaimError as e:
        logger.debug(f"Token claims validation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token claims: {e}",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.PyJWTError as e:
        logger.debug(f"Token validation error: {e}")
        raise credentials_exception from e
    except ValueError:
        logger.error(f"Invalid UUID format in token 'sub' field: {user_id_str}")
        raise credentials_exception
    except Exception as e:
        logger.exception(f"Unexpected error during token validation: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred.",
        ) from e


# Type alias for dependency injection clarity
CurrentUserUUID = Annotated[uuid.UUID, Depends(get_current_user_id)]
