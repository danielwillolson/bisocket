"""Issue 3: an embedder must be able to make a missing CRYPTO_KEY fail.

`get_crypto_key()` warns and falls back to a publicly known default. A warning in
a long-running server's log is easy to miss, and the failure mode is silent: the
service comes up and runs happily on `'secret-lol'`. `require_key` turns that
into a startup failure.
"""
import pytest

import bisocket
from bisocket import Client, Server, ENCRYPTION_OFF, ENCRYPTION_FASTER
from bisocket import main as bisocket_main


@pytest.fixture
def no_crypto_key(monkeypatch):
    monkeypatch.delenv('CRYPTO_KEY', raising=False)
    monkeypatch.delenv('BISOCKET_REQUIRE_KEY', raising=False)
    # The fallback warning is once-per-process; reset it so it does not depend
    # on which tests ran first.
    monkeypatch.setattr(bisocket_main, '_crypto_key_warned', False, raising=False)


def test_server_with_require_key_refuses_to_start_without_a_key(no_crypto_key):
    with pytest.raises(bisocket.MissingCryptoKey):
        Server('127.0.0.1', 1, lambda r: None, require_key=True)


def test_client_with_require_key_refuses_to_start_without_a_key(no_crypto_key):
    with pytest.raises(bisocket.MissingCryptoKey):
        Client('127.0.0.1', 1, lambda m: None, require_key=True)


def test_require_key_is_satisfied_by_a_real_key(no_crypto_key, monkeypatch):
    monkeypatch.setenv('CRYPTO_KEY', 'a-real-key')
    server = Server('127.0.0.1', 1, lambda r: None, require_key=True)
    assert server.encryption_service.key == \
        bisocket_main.EncryptionService.derive_key('a-real-key')


def test_require_key_does_not_apply_when_encryption_is_off(no_crypto_key):
    """With no encryption there is no key in play, so requiring one is nonsense."""
    server = Server('127.0.0.1', 1, lambda r: None,
                    encryption=ENCRYPTION_OFF, require_key=True)
    assert server.encryption == ENCRYPTION_OFF
    assert server.encryption_service is None

    client = Client('127.0.0.1', 1, lambda m: None,
                    encryption=ENCRYPTION_OFF, require_key=True)
    assert client.encryption == ENCRYPTION_OFF


def test_env_var_turns_the_requirement_on(no_crypto_key, monkeypatch):
    monkeypatch.setenv('BISOCKET_REQUIRE_KEY', '1')
    with pytest.raises(bisocket.MissingCryptoKey):
        Server('127.0.0.1', 1, lambda r: None)
    with pytest.raises(bisocket.MissingCryptoKey):
        Client('127.0.0.1', 1, lambda m: None)


def test_an_explicit_argument_overrides_the_env_var(no_crypto_key, monkeypatch):
    monkeypatch.setenv('BISOCKET_REQUIRE_KEY', '1')
    # Opting out in code beats the environment, so a test harness inside a
    # production image can still run.
    server = Server('127.0.0.1', 1, lambda r: None, require_key=False)
    assert server.encryption == bisocket.ENCRYPTION_SECURE


def test_default_behaviour_is_unchanged(no_crypto_key, capsys):
    """Without require_key, the fallback and its warning must still happen."""
    server = Server('127.0.0.1', 1, lambda r: None, encryption=ENCRYPTION_FASTER)
    assert server.encryption_service.key == \
        bisocket_main.EncryptionService.derive_key(bisocket_main.DEFAULT_CRYPTO_KEY)
    assert 'CRYPTO_KEY is not set' in capsys.readouterr().err


@pytest.mark.parametrize('value,expected', [
    ('1', True), ('true', True), ('TRUE', True), ('yes', True), ('on', True),
    ('required', True), ('0', False), ('false', False), ('no', False),
    ('', False), ('  ', False),
])
def test_env_var_parsing(no_crypto_key, monkeypatch, value, expected):
    monkeypatch.setenv('BISOCKET_REQUIRE_KEY', value)
    assert bisocket.resolve_require_key() is expected


def test_explicit_values_bypass_the_env_var(no_crypto_key, monkeypatch):
    monkeypatch.setenv('BISOCKET_REQUIRE_KEY', '0')
    assert bisocket.resolve_require_key(True) is True
    monkeypatch.setenv('BISOCKET_REQUIRE_KEY', '1')
    assert bisocket.resolve_require_key(False) is False


def test_unset_env_var_means_no_requirement(no_crypto_key):
    assert bisocket.resolve_require_key() is False


def test_the_error_names_what_to_do(no_crypto_key):
    with pytest.raises(bisocket.MissingCryptoKey) as excinfo:
        bisocket_main.get_crypto_key(require=True)
    text = str(excinfo.value)
    assert 'CRYPTO_KEY' in text and 'require_key' in text
