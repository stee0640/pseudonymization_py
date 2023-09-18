from abc import ABC, abstractmethod
import re

class Normalizer(ABC):
    @abstractmethod
    def transform(self, source: str) -> bytes:
        pass

class DefaultCprNormalizer(Normalizer):
    def transform(self, source: str) -> bytes:
        # Transform the CPR-number to a suitable byte sequence
        return re.sub("[^0-9]", "", source).encode("utf-8")
    
class NullNormalizer(Normalizer):
    def transform(self, source: str) -> bytes:
        # Just transform from string to bytes
        return source.encode("utf-8")