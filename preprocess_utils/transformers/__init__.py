from typing import Any, List, MutableMapping


def transform_list_to_string(_list: List[Any]) -> str:
    return ", ".join(map(lambda v: str(v), _list))


def transform_nested_dict_to_dict(
    _dict: MutableMapping[str, Any]
) -> MutableMapping[str, str]:
    _return = {}
    for _key, _val in _dict.items():
        _key = _key.replace(".", "_")
        if isinstance(_val, dict):
            for ani_key, ani_val in transform_nested_dict_to_dict(_val).items():
                _return[f"{_key}_{ani_key}"] = ani_val
        elif isinstance(_val, list):
            if all([not isinstance(v, dict) and not isinstance(v, list) for v in _val]):
                _return[_key] = transform_list_to_string(_val)
                continue
            for i, v in enumerate(_val):
                _r_key = f"{_key}_{i}"
                if isinstance(v, dict):
                    for k, v in transform_nested_dict_to_dict(v).items():
                        _return[f"{_r_key}_{k}"] = v
                elif isinstance(v, list):
                    _return.update(transform_nested_dict_to_dict({_r_key: v}))
        else:
            _return[_key] = str(_val)
    return _return
