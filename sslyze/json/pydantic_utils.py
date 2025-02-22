from typing import Any
from typing import Annotated


from pydantic import BaseModel, BeforeValidator, ConfigDict


class BaseModelWithOrmMode(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class BaseModelWithOrmModeAndForbid(BaseModel):
    model_config = ConfigDict(extra="forbid", from_attributes=True)


def _handle_enum_name(enum_value: Any) -> str:
    if isinstance(enum_value, str):
        return enum_value
    else:
        return enum_value.name


# Use StrFromEnumValueName for JSON fields that need to be populated using the real object's field `value.name`.
StrFromEnumValueName = Annotated[str, BeforeValidator(_handle_enum_name)]
