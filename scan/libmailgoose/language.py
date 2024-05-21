from enum import Enum
from pathlib import Path


class Language(Enum):
    pass


for line in open(Path(__file__).parent / "languages.txt"):
    setattr(Language, line.strip(), line.strip())
