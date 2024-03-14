from typing import Any, Callable, MutableMapping, Optional
from copy import deepcopy
from json import dumps


class _NotSet:
    pass


class Mapper:
    def __init__(
        self,
        data: MutableMapping[str, Any],
        *,
        default_delimiter=".",
        default_value_on_error=_NotSet()
    ) -> None:
        self._data = data
        self._default_delimiter = default_delimiter
        self._default_value_on_error = default_value_on_error

    def get(
        self,
        keys: str,
        *,
        default: Any = _NotSet(),
        transformer: Optional[Callable[[Any], Any]] = None,
        delimiter: Optional[str] = None
    ):
        _keys = keys.split(delimiter if delimiter else self._default_delimiter)
        pointer = self._data
        try:
            for k in _keys:
                if isinstance(pointer, list):
                    k = int(k)
                pointer = pointer[k]
            if transformer:
                return transformer(deepcopy(pointer))
            return pointer
        except Exception as e:
            if not isinstance(default, _NotSet):
                return default
            elif not isinstance(self._default_value_on_error, _NotSet):
                return self._default_value_on_error
            raise e

    def __str__(self):
        return str(self._data)

    def __repr__(self):
        return dumps(self._data)
