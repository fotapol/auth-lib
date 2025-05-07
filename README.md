# Auth Library

The Auth Library provides JWT-based authentication utilities for FastBoosty microservices. It is designed to be used as a shared dependency for verifying and extracting user identity from JWT tokens in FastAPI-based services.

## Tech Stack

- **FastAPI** – Web framework
- **PyJWT** – JWT decoding
- **Python** – Core language
- **Pytest** – Test framework

## Features

- JWT token validation and decoding
- Return User ID extraction from token

## Usage

Import and use the `CurrentUserUUID` dependency in your FastAPI endpoints to require JWT authentication:

```python
from auth_lib.auth import CurrentUserUUID
from fastapi import APIRouter

router = APIRouter()

@router.get("/protected")
async def protected_route(user_uuid: CurrentUserUUID):
    return {"user_uuid": user_uuid}
```

## Configuration

Set the following environment variable in your service:

- `JWT_SECRET_KEY` – Secret key for verifying JWT tokens (required). It must be the same key which you use in the [`auth_service`](https://github.com/fotapol/fastboosty-auth_service)

## Testing

Run tests with:

```bash
pytest
```

## Security Notice

- **Do not commit real secret keys or credentials to the repository.**
- Always use environment variables for secrets in production.
- This library does not generate tokens, only verifies them.

## License

The Auth Library is licensed under the terms of the MIT license.
