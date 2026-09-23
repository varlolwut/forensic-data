class ContractError(ValueError):
    """Base error for versioned contract loading and resolution."""


class ContractFileError(ContractError):
    """A contract or referenced artifact could not be read safely."""


class ContractYamlError(ContractError):
    """A contract file is not one strict YAML document."""


class DuplicateYamlKeyError(ContractYamlError):
    """A YAML mapping contains a duplicate key."""


class ContractValidationError(ContractError):
    """A contract value violates the versioned configuration shape."""


class ContractReferenceError(ContractError):
    """A contract reference cannot be resolved consistently."""


class SqlArtifactError(ContractError):
    """A referenced SQL artifact is missing or invalid."""


class UnsupportedContractError(ContractError):
    """A syntactically valid contract requests an unsupported invariant or profile."""


class ScopeValueError(ContractError):
    """Concrete scope parameters do not satisfy their typed definition."""
