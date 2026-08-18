"""
Shared pytest configuration.

Two jobs:

1. **Never call a paid API from a test.** An autouse fixture replaces every
   OpenAI client the app holds with a deterministic fake. Before this existed a
   full run made hundreds of billable gpt-4o calls, which meant the suite could
   not run in CI and could not run offline.

2. **Keep the network-dependent suite out of the default run.** ``test_remote_api``
   targets a live deployment and defaults to a placeholder host, so a bare
   ``pytest`` used to hang on DNS and then emit 28 errors. It now requires
   ``--remote`` plus ``TEST_BASE_URL``.
"""
import os

import pytest

# ---------------------------------------------------------------------------
# Remote-suite gating
# ---------------------------------------------------------------------------

def pytest_addoption(parser):
    parser.addoption(
        "--remote",
        action="store_true",
        default=False,
        help="Run tests that hit a live deployed backend (needs TEST_BASE_URL).",
    )


def pytest_collection_modifyitems(config, items):
    """Skip the live-deployment suite unless explicitly requested."""
    if config.getoption("--remote"):
        if not os.getenv("TEST_BASE_URL"):
            pytest.exit(
                "--remote requires TEST_BASE_URL to point at a real deployment",
                returncode=4,
            )
        return

    skip_remote = pytest.mark.skip(
        reason="live-deployment test; pass --remote and set TEST_BASE_URL to run"
    )
    for item in items:
        if "test_remote_api" in str(item.fspath):
            item.add_marker(skip_remote)


# ---------------------------------------------------------------------------
# Deterministic fake LLM
# ---------------------------------------------------------------------------

class _FakeUsage:
    def __init__(self, prompt_tokens=120, completion_tokens=30):
        self.prompt_tokens = prompt_tokens
        self.completion_tokens = completion_tokens


class _FakeMessage:
    def __init__(self, content):
        self.content = content


class _FakeChoice:
    def __init__(self, content):
        self.message = _FakeMessage(content)


class _FakeCompletion:
    """Mimics the shape the app reads: .choices[0].message.content and .usage."""

    def __init__(self, content):
        self.choices = [_FakeChoice(content)]
        self.usage = _FakeUsage()


# In-character, ends with a question mark, contains a red-flag keyword and no
# guardrail-violating text -- satisfies the persona assertions in the suite.
FAKE_REPLY = (
    "oh no beta this sounds very urgent, i am worried. "
    "what is your phone number so i can call you?"
)


class _FakeCompletions:
    def __init__(self, reply):
        self._reply = reply
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return _FakeCompletion(self._reply)


class _FakeAsyncCompletions(_FakeCompletions):
    async def create(self, **kwargs):  # type: ignore[override]
        self.calls.append(kwargs)
        return _FakeCompletion(self._reply)


class _FakeChat:
    def __init__(self, completions):
        self.completions = completions


class FakeOpenAI:
    """Stand-in for openai.OpenAI."""

    def __init__(self, *args, reply=FAKE_REPLY, **kwargs):
        self.init_kwargs = kwargs
        self.chat = _FakeChat(_FakeCompletions(reply))


class FakeAsyncOpenAI:
    """Stand-in for openai.AsyncOpenAI."""

    def __init__(self, *args, reply=FAKE_REPLY, **kwargs):
        self.init_kwargs = kwargs
        self.chat = _FakeChat(_FakeAsyncCompletions(reply))


@pytest.fixture(autouse=True)
def no_paid_llm_calls(monkeypatch):
    """
    Replace every live OpenAI client with a fake, for every test.

    Patches the already-constructed singletons (the services build their clients
    at import time) as well as the classes, so code that instantiates a client
    per request also gets the fake.
    """
    import openai

    monkeypatch.setattr(openai, "OpenAI", FakeOpenAI, raising=False)
    monkeypatch.setattr(openai, "AsyncOpenAI", FakeAsyncOpenAI, raising=False)

    # Swap the clients on the long-lived service singletons.
    try:
        from app.api import routes

        monkeypatch.setattr(routes.ai_agent, "client", FakeAsyncOpenAI(), raising=False)
        monkeypatch.setattr(
            routes.scam_detector, "client", FakeOpenAI(), raising=False
        )
        monkeypatch.setattr(
            routes.intelligence_extractor, "client", FakeOpenAI(), raising=False
        )
    except Exception:
        # Tests that don't import the app don't need the swap.
        pass

    yield


@pytest.fixture(autouse=True)
def disable_rate_limiter():
    """
    Turn the per-IP rate limiter off for the suite.

    Every TestClient request originates from the same synthetic client address,
    so the 30/minute cap on /conversation throttles the suite itself rather than
    testing anything: the ~50 conversation tests would 429 partway through.
    Rate limiting is asserted deliberately in
    ``test_hardening.TestRateLimiting`` instead, which re-enables it.
    """
    from app.core.limiter import limiter

    previous = limiter.enabled
    limiter.enabled = False
    yield
    limiter.enabled = previous


@pytest.fixture
def rate_limiter_enabled():
    """Opt back in to real rate limiting, with fresh counters."""
    from app.core.limiter import limiter

    limiter.enabled = True
    limiter.reset()
    yield limiter
    limiter.reset()
    limiter.enabled = False


@pytest.fixture(autouse=True)
def reset_cost_guard():
    """Each test starts with a clean spend ledger and provider health."""
    from app.services.cost_guard import cost_guard, provider_health

    cost_guard.reset()
    provider_health.consecutive_auth_failures = 0
    provider_health.last_error = None
    yield
    cost_guard.reset()
    provider_health.consecutive_auth_failures = 0


@pytest.fixture
def admin_headers():
    """Header form of admin auth, for server-to-server style calls."""
    from app.core.config import settings

    return {"x-admin-key": settings.admin_api_key}
