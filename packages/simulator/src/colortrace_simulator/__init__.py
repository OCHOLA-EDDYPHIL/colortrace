"""Fenced execution of approved actions in the local simulator namespace."""

from .gcs_publication import (
    GCS_SIMULATOR_REQUIRED_PERMISSIONS,
    GcsPublicationPolicy,
    GcsPublicationPort,
    StorageClient,
)
from .models import (
    ActionClaim,
    ActionSnapshot,
    BoundSimulatorAction,
    DispatchIdentity,
    PreparedPublication,
    PromotionResult,
    PublicationOperationState,
    PublicationPort,
    RecoveryArtifact,
    RecoveryPublicationPort,
    RecoverySnapshot,
    StoredDispatchProof,
    StoredDispatchSource,
)
from .service import SimulatorActionService

__all__ = [
    "ActionClaim",
    "ActionSnapshot",
    "BoundSimulatorAction",
    "DispatchIdentity",
    "GCS_SIMULATOR_REQUIRED_PERMISSIONS",
    "GcsPublicationPolicy",
    "GcsPublicationPort",
    "PreparedPublication",
    "PromotionResult",
    "PublicationOperationState",
    "PublicationPort",
    "RecoveryArtifact",
    "RecoveryPublicationPort",
    "RecoverySnapshot",
    "StoredDispatchProof",
    "StoredDispatchSource",
    "StorageClient",
    "SimulatorActionService",
]
