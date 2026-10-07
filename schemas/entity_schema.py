"""Entity models for identities, infrastructure, and observed artifacts."""

from dataclasses import dataclass, field


@dataclass
class User:
    """A person or account observed in directory and security data."""

    user_id: str
    display_name: str | None = None
    email: str | None = None
    role: str | None = None
    business_unit: str | None = None
    functional_unit: str | None = None
    department: str | None = None
    team: str | None = None
    supervisor_user_id: str | None = None
    attributes: dict[str, object] = field(default_factory=dict)


@dataclass
class Device:
    """An endpoint or other device associated with security activity."""

    device_id: str
    hostname: str | None = None
    owner_user_id: str | None = None
    device_type: str | None = None
    operating_system: str | None = None
    first_seen: str | None = None
    last_seen: str | None = None
    attributes: dict[str, object] = field(default_factory=dict)


@dataclass
class IPAddress:
    """An IPv4 or IPv6 address observed in network telemetry."""

    address: str
    version: int | None = None
    first_seen: str | None = None
    last_seen: str | None = None
    reputation: str | None = None
    attributes: dict[str, object] = field(default_factory=dict)


@dataclass
class Domain:
    """A DNS domain associated with URLs, email, or network activity."""

    domain_name: str
    registered_domain: str | None = None
    first_seen: str | None = None
    last_seen: str | None = None
    reputation: str | None = None
    associated_ip_addresses: list[str] = field(default_factory=list)
    attributes: dict[str, object] = field(default_factory=dict)


@dataclass
class URL:
    """A web resource observed in HTTP or other network telemetry."""

    url: str
    domain_name: str | None = None
    first_seen: str | None = None
    last_seen: str | None = None
    reputation: str | None = None
    attributes: dict[str, object] = field(default_factory=dict)


@dataclass
class FileEntity:
    """A file observed on an endpoint, in an email, or in an investigation."""

    file_name: str
    file_id: str | None = None
    file_hash: str | None = None
    path: str | None = None
    size_bytes: int | None = None
    owner_user_id: str | None = None
    device_id: str | None = None
    first_seen: str | None = None
    attributes: dict[str, object] = field(default_factory=dict)


@dataclass
class Email:
    """An email message and its sender, recipients, and attachment references."""

    message_id: str
    sender: str | None = None
    to: list[str] = field(default_factory=list)
    cc: list[str] = field(default_factory=list)
    bcc: list[str] = field(default_factory=list)
    sent_at: str | None = None
    subject: str | None = None
    body: str | None = None
    size_bytes: int | None = None
    attachment_count: int | None = None
    attachment_ids: list[str] = field(default_factory=list)
    attributes: dict[str, object] = field(default_factory=dict)


@dataclass
class SMS:
    """A text message and any links or entities extracted from it."""

    message_id: str
    sender: str | None = None
    recipients: list[str] = field(default_factory=list)
    sent_at: str | None = None
    body: str | None = None
    urls: list[str] = field(default_factory=list)
    attributes: dict[str, object] = field(default_factory=dict)


@dataclass
class Malware:
    """A malware sample or family tracked during incident reconstruction."""

    malware_id: str
    name: str | None = None
    family: str | None = None
    hashes: dict[str, str] = field(default_factory=dict)
    file_names: list[str] = field(default_factory=list)
    first_seen: str | None = None
    last_seen: str | None = None
    severity: str | None = None
    confidence: float = 1.0
    attributes: dict[str, object] = field(default_factory=dict)
