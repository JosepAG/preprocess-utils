from typing import Any


class Extensions(dict):
    
    def __init__(self, **kwargs):
        self.__add(**kwargs)
    
    def __setitem__(self, __key: Any, __value: Any) -> None:
        self.__add(**{__key:__value})

    def update(self, **kwargs):
        self.__add(**kwargs)
    
    def __add(self, **kwargs):
        for k, v in kwargs.items():
            if not v:
                continue
            super().__setitem__(k, str(v))
