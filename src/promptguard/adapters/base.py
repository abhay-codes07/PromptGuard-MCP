"""Abstract base for LLM adapters.

Every adapter (Anthropic, OpenAI, generic HTTP) implements this interface so the
rest of PromptGuard can target arbitrary LLM endpoints without caring about
provider-specific quirks.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from promptguard.models import ChatResponse, Message


class LLMAdapter(ABC):
    """Adapter for sending chat messages to an LLM and getting a normalised response.

    Implementations should:

    * Be cheap to construct (no network in ``__init__``).
    * Read credentials from environment variables, with optional override via
      constructor args for testing.
    * Translate provider errors into either a normalised ``ChatResponse`` (with
      ``finish_reason='error'``) or a Python exception — pick one and document.
    * Never log message contents at INFO level. Attack prompts can be sensitive.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Short, stable adapter name (e.g. ``"anthropic"``)."""

    @abstractmethod
    async def chat(self, messages: list[Message], **kwargs: object) -> ChatResponse:
        """Send messages to the LLM and return a normalised response.

        Args:
            messages: Ordered chat history. First message may be a system prompt.
            **kwargs: Provider-specific extras (e.g. ``model``, ``temperature``).
                Adapters MAY ignore unknown kwargs.

        Returns:
            The LLM's response, with the raw provider payload preserved for
            debugging in ``response.raw``.

        Raises:
            httpx.HTTPError: For transport-level failures.
            ValueError: For misconfiguration (missing API key, etc.).
        """
