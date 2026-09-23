from collections.abc import Callable, Hashable
from pathlib import Path
from typing import cast, final

import yaml
from yaml.events import AliasEvent
from yaml.nodes import MappingNode, Node, ScalarNode
from yaml.reader import ReaderError

from forensic_data.contracts.errors import (
    ContractFileError,
    ContractValidationError,
    ContractYamlError,
    DuplicateYamlKeyError,
)

type YamlScalar = bool | int | str | None
type YamlValue = YamlScalar | tuple["YamlValue", ...] | dict[str, "YamlValue"]
type YamlObject = dict[str, YamlValue]

_MAX_CONTRACT_BYTES = 1 * 1024 * 1024
_MAX_YAML_COMPOSED_NODES = 10_000
_MAX_YAML_DEPTH = 64


@final
class _UniqueKeySafeLoader(yaml.SafeLoader):
    def __init__(self, stream: str, source_name: str) -> None:
        super().__init__(stream)
        self.source_name = source_name
        self.composed_nodes = 0
        self.compose_depth = 0

    def compose_node(self, parent: Node | None, index: int | None) -> Node:
        check_event = cast(
            Callable[[type[AliasEvent]], bool],
            self.check_event,  # pyright: ignore[reportUnknownMemberType]
        )
        if check_event(AliasEvent):
            raise ContractYamlError(
                f"contract YAML aliases are unsupported: path={self.source_name!r}"
            )
        self.composed_nodes += 1
        if self.composed_nodes > _MAX_YAML_COMPOSED_NODES:
            raise ContractYamlError(
                f"contract YAML contains more than {_MAX_YAML_COMPOSED_NODES} composed nodes: "
                f"path={self.source_name!r}"
            )
        self.compose_depth += 1
        try:
            if self.compose_depth > _MAX_YAML_DEPTH:
                raise ContractYamlError(
                    f"contract YAML nesting exceeds {_MAX_YAML_DEPTH} composed levels: "
                    f"path={self.source_name!r}"
                )
            compose = cast(
                Callable[[Node | None, int | None], Node],
                super().compose_node,  # pyright: ignore[reportUnknownMemberType]
            )
            return compose(parent, index)
        finally:
            self.compose_depth -= 1


def load_yaml_object(path: Path) -> YamlObject:
    validated_path = _require_path(path)
    source_name = str(validated_path)
    read_failure: ContractFileError | None = None
    raw = b""
    try:
        with validated_path.open("rb") as stream:
            raw = stream.read(_MAX_CONTRACT_BYTES + 1)
    except (OSError, ValueError) as error:
        read_failure = ContractFileError(
            f"contract file cannot be read: path={source_name!r}, error_type={type(error).__name__}"
        )
    if read_failure is not None:
        raise read_failure
    if len(raw) > _MAX_CONTRACT_BYTES:
        raise ContractFileError(
            f"contract file exceeds the {_MAX_CONTRACT_BYTES}-byte parser limit: "
            f"path={source_name!r}, bytes={len(raw)}"
        )

    decode_failure: ContractFileError | None = None
    text = ""
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        decode_failure = ContractFileError(
            f"contract file is not strict UTF-8: path={source_name!r}, "
            f"byte_start={error.start}, byte_end={error.end}, reason={error.reason}"
        )
    if decode_failure is not None:
        raise decode_failure

    loader: _UniqueKeySafeLoader | None = None
    parsed: object = None
    parse_failure: ContractYamlError | None = None
    try:
        loader = _UniqueKeySafeLoader(text, source_name)
        parsed = cast(object, loader.get_single_data())
    except DuplicateYamlKeyError as error:
        parse_failure = error
    except ContractYamlError as error:
        parse_failure = error
    except (yaml.YAMLError, ReaderError) as error:
        mark = getattr(error, "problem_mark", None)
        location = ""
        if mark is not None:
            location = f", line={mark.line + 1}, column={mark.column + 1}"
        parse_failure = ContractYamlError(
            f"contract file must contain one valid safe YAML document: "
            f"path={source_name!r}{location}, error_type={type(error).__name__}"
        )
    except ValueError as error:
        parse_failure = ContractYamlError(
            f"contract file contains a YAML scalar that cannot be constructed safely: "
            f"path={source_name!r}, error_type={type(error).__name__}"
        )
    except RecursionError:
        parse_failure = ContractYamlError(
            f"contract YAML nesting exceeds the parser limit: path={source_name!r}"
        )
    finally:
        if loader is not None:
            dispose = cast(
                Callable[[], None],
                loader.dispose,  # pyright: ignore[reportUnknownMemberType]
            )
            dispose()
    if parse_failure is not None:
        raise parse_failure

    freeze_failure: ContractValidationError | None = None
    frozen: YamlValue = None
    try:
        frozen = _freeze_yaml_value(parsed, "contract", 0)
    except RecursionError:
        freeze_failure = ContractValidationError(
            "contract YAML nesting exceeds the immutable-value limit"
        )
    if freeze_failure is not None:
        raise freeze_failure
    if type(frozen) is not dict:
        raise ContractValidationError("contract document root must be a mapping")
    return frozen


def _construct_unique_mapping(
    loader: _UniqueKeySafeLoader,
    node: Node,
) -> dict[object, object]:
    if not isinstance(node, MappingNode):
        raise ContractYamlError("YAML mapping constructor received a non-mapping node")
    raw_keys: set[tuple[str, str]] = set()
    for key_node, _ in node.value:
        if not isinstance(key_node, ScalarNode):
            continue
        identity = (key_node.tag, key_node.value)
        if identity in raw_keys:
            raise DuplicateYamlKeyError(
                f"contract YAML contains duplicate mapping key: path={loader.source_name!r}, "
                f"key={key_node.value!r}, line={key_node.start_mark.line + 1}, "
                f"column={key_node.start_mark.column + 1}"
            )
        raw_keys.add(identity)
    loader.flatten_mapping(node)
    construct_object = cast(
        Callable[[Node, bool], object],
        loader.construct_object,  # pyright: ignore[reportUnknownMemberType]
    )
    result: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = construct_object(key_node, True)
        if not isinstance(key, Hashable):
            raise ContractYamlError(
                f"contract YAML mapping key must be hashable: path={loader.source_name!r}"
            )
        if key in result:
            raise DuplicateYamlKeyError(
                f"contract YAML contains duplicate mapping key: path={loader.source_name!r}, "
                f"key={key!r}, line={key_node.start_mark.line + 1}, "
                f"column={key_node.start_mark.column + 1}"
            )
        value = construct_object(value_node, True)
        result[key] = value
    return result


def _freeze_yaml_value(
    value: object,
    context: str,
    depth: int,
) -> YamlValue:
    if depth > _MAX_YAML_DEPTH:
        raise ContractValidationError(
            f"{context} exceeds the maximum YAML nesting depth {_MAX_YAML_DEPTH}"
        )
    if value is None or type(value) in (bool, int, str):
        return cast(YamlScalar, value)
    if type(value) is float:
        raise ContractValidationError(
            f"{context} contains a floating-point value; use an exact typed string or integer"
        )

    if type(value) is list:
        values = cast(list[object], value)
        return tuple(
            _freeze_yaml_value(
                item,
                f"{context}[{index}]",
                depth + 1,
            )
            for index, item in enumerate(values)
        )
    if type(value) is dict:
        mapping = cast(dict[object, object], value)
        frozen_mapping: dict[str, YamlValue] = {}
        for key, item in mapping.items():
            if type(key) is not str:
                raise ContractValidationError(f"{context} mapping keys must be strings")
            frozen_mapping[key] = _freeze_yaml_value(
                item,
                f"{context}.{key}",
                depth + 1,
            )
        return frozen_mapping
    raise ContractValidationError(
        f"{context} contains unsupported YAML value type {type(value).__name__}; "
        "only null, booleans, exact integers, strings, sequences, and mappings are permitted"
    )


def _require_path(value: object) -> Path:
    if not isinstance(value, Path):
        raise TypeError("contract path must be a pathlib.Path")
    return value


_UniqueKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)
