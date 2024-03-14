from enum import Enum


class Severity(int, Enum):
    Low = 3
    Medium = 5
    High = 7
    Critical = 9
