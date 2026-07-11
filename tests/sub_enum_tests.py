from collections.abc import Generator
from unittest.mock import AsyncMock
from unittest.mock import Mock
from unittest.mock import patch

import aiohttp
import pytest
from sub_enum import async_dns_lookup
from sub_enum import certspotter_get_subs
from sub_enum import crt_get_subs
from sub_enum import fallback_dns_lookup
from sub_enum import fetch_url

# Update this import to match your actual script name
from sub_enum import validate_domain
from sub_enum import web_archive

# Test data
VALID_DOMAINS = [
    "example.com",
    "sub.example.com",
    "test-domain.com",
    "domain123.co.uk",
]

INVALID_DOMAINS = [
    "",
    "invalid",
    "not.a.domain",
    "test@email.com",
    "http://example.com",
    "domain..com",
]


@pytest.mark.parametrize("domain", VALID_DOMAINS)
def test_validate_domain_valid(domain: str) -> None:
    """Test domain validation with valid domains."""
    assert validate_domain(domain) is True


@pytest.mark.parametrize("domain", INVALID_DOMAINS)
def test_validate_domain_invalid(domain: str) -> None:
    """Test domain validation with invalid domains."""
    assert validate_domain(domain) is False


@pytest.mark.asyncio(loop_scope="session")
@patch("dns.asyncresolver.Resolver")
async def test_async_dns_lookup_success(mock_resolver) -> None:
    """Test successful DNS lookup."""
    # Setup mock
    mock_answer = Mock()
    mock_answer.__str__ = Mock(return_value="93.184.216.34")
    mock_resolver.return_value.resolve.return_value = [mock_answer]

    result = await async_dns_lookup("example.com")
    assert result == "93.184.216.34"
    mock_resolver.return_value.resolve.assert_called_once_with("example.com", "A")


@pytest.mark.asyncio(loop_scope="session")
@patch("dns.asyncresolver.Resolver")
async def test_async_dns_lookup_nxdomain(mock_resolver) -> None:
    """Test DNS lookup with NXDOMAIN response."""
    mock_resolver.return_value.resolve.side_effect = dns.resolver.NXDOMAIN()

    with patch("sub_enum.fallback_dns_lookup", return_value=None):
        result = await async_dns_lookup("nonexistent.com")
        assert result is None


@pytest.mark.asyncio(loop_scope="session")
async def test_fetch_url_success() -> None:
    """Test successful URL fetch."""
    mock_response = {
        "status": "success",
        "data": ["test.example.com"],
    }

    with patch("aiohttp.ClientSession") as mock_session:
        mock_context = AsyncMock()
        mock_context.status = 200
        mock_context.json.return_value = mock_response
        mock_session.return_value.__aenter__.return_value.get.return_value.__aenter__.return_value = mock_context

        result = await fetch_url("https://api.example.com")
        assert result == mock_response


@pytest.mark.asyncio(loop_scope="session")
async def test_fetch_url_failure() -> None:
    """Test URL fetch with connection error."""
    with patch("aiohttp.ClientSession") as mock_session:
        mock_session.return_value.__aenter__.return_value.get.side_effect = aiohttp.ClientError()
        result = await fetch_url("https://api.example.com")
        assert result is None


@pytest.mark.asyncio(loop_scope="session")
async def test_crt_get_subs() -> None:
    """Test crt.sh subdomain enumeration."""
    mock_html = """
    <table>
        <tr></tr>
        <tr><td>1</td><td>2</td><td>3</td><td>4</td><td>sub1.example.com</td></tr>
        <tr><td>1</td><td>2</td><td>3</td><td>4</td><td>sub2.example.com</td></tr>
    </table>
    """

    with patch("aiohttp.ClientSession") as mock_session:
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text.return_value = mock_html
        mock_session.return_value.__aenter__.return_value.get.return_value.__aenter__.return_value = mock_response

        subs = [sub async for sub in crt_get_subs("example.com")]
        assert len(subs) == 2
        assert "sub1.example.com" in subs
        assert "sub2.example.com" in subs


@pytest.mark.asyncio(loop_scope="session")
async def test_certspotter_get_subs() -> None:
    """Test certspotter subdomain enumeration."""
    mock_response = [
        {
            "dns_names": ["*.example.com", "sub1.example.com"],
        },
        {
            "dns_names": ["sub2.example.com", "sub3.example.com"],
        },
    ]

    with patch("sub_enum.fetch_url") as mock_fetch:
        mock_fetch.return_value = mock_response
        subs = [sub async for sub in certspotter_get_subs("example.com")]
        assert len(subs) == 4
        assert "example.com" in subs
        assert "sub1.example.com" in subs
        assert "sub2.example.com" in subs
        assert "sub3.example.com" in subs


@pytest.mark.asyncio(loop_scope="session")
async def test_web_archive() -> None:
    """Test web.archive.org subdomain enumeration."""
    mock_response = [
        ["header"],  # First row is header
        ["http://sub1.example.com/page"],
        ["http://sub2.example.com:80/page"],
    ]

    with patch("sub_enum.fetch_url") as mock_fetch:
        mock_fetch.return_value = mock_response
        subs = [sub async for sub in web_archive("example.com")]
        assert len(subs) == 2
        assert "sub1.example.com" in subs
        assert "sub2.example.com" in subs


# Fixture for common mock setup
@pytest.fixture
def mock_session() -> Generator[Mock]:
    """Fixture to provide a mock aiohttp ClientSession.

    Yields:
        Mock: A mock aiohttp ClientSession.
    """
    with patch("aiohttp.ClientSession") as mock:
        yield mock


# Integration-style test
@pytest.mark.asyncio(loop_scope="session")
async def test_fallback_dns_lookup_integration() -> None:
    """Test fallback DNS lookup with Google DNS."""
    mock_response = {
        "Answer": [
            {"data": "93.184.216.34"},
        ],
    }

    with patch("sub_enum.fetch_url", AsyncMock(return_value=mock_response)) as mock_fetch:
        result = await fallback_dns_lookup("example.com")
        assert result == "93.184.216.34"
        mock_fetch.assert_called_once_with(
            "https://dns.google.com/resolve?name=example.com&type=A",
        )
