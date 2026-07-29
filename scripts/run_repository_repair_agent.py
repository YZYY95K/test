"""Run the fixed repository-repair benchmark with an LLM patch provider.

Credentials are intentionally environment-only.  This entry point has no
API-key or base-URL command-line option and never prints prompts, source code,
environment values, or raw model responses.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import math
import os
import re
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Protocol, cast

import yaml
from pydantic import Field, ValidationError, model_validator

ROOT = Path(__file__).resolve().parents[1]
for import_path in (ROOT, ROOT / "src"):
    if str(import_path) not in sys.path:
        sys.path.insert(0, str(import_path))

from devflow.llm_client import CompletionResult, LLMClient  # noqa: E402
from scripts.repository_repair_executor import (  # noqa: E402
    FileReplacement,
    PatchProposal,
    PatchProviderError,
    PatchRequest,
    execute_repair_benchmark,
    load_repair_report,
)
from scripts.run_repository_benchmark import (  # noqa: E402
    RepairBenchmarkManifest,
    RepairBenchmarkReport,
    RepairCostProvenance,
    StrictBenchmarkModel,
    load_repair_manifest,
    validate_repair_manifest,
    validate_repair_report,
)

SYSTEM_PROMPT = """你是固定版本开源仓库的补丁生成器。You repair one pinned source task.
你只能依据用户消息中的 issue、target_paths、mutated_sources 和 failure_summary。
The manifest, mutation oracle, and pre-mutation source are unavailable and must never be requested.
只返回一个 JSON 对象，不得使用 Markdown fence、解释、shell 命令或 unified diff。
Return exactly: {"replacements":[{"path":"...","expected_sha256":"...","content":"complete UTF-8 file"}]}.
Every path must be in target_paths; expected_sha256 must copy that mutated source digest.
Do not include token counts, prices, human-approval claims, or any additional field."""


class CompletionClient(Protocol):
    default_model: str | None

    async def complete_with_usage(
        self,
        prompt: str,
        *,
        model: str | None = None,
        temperature: float = 0.2,
        system: str | None = None,
    ) -> CompletionResult: ...


class ModelPatchPayload(StrictBenchmarkModel):
    """Only fields the model is permitted to claim."""

    replacements: list[FileReplacement] = Field(min_length=1, max_length=8)

    @model_validator(mode="after")
    def _unique_paths(self) -> ModelPatchPayload:
        paths = [item.path for item in self.replacements]
        if len(paths) != len(set(paths)):
            raise ValueError("model replacement paths must be unique")
        return self


class PriceValues(StrictBenchmarkModel):
    input: float = Field(gt=0)
    cached_input: float = Field(gt=0)
    output: float = Field(gt=0)

    @model_validator(mode="after")
    def _cached_price_is_not_higher(self) -> PriceValues:
        if self.cached_input > self.input:
            raise ValueError("cached input price cannot exceed ordinary input price")
        return self


class CostMethod(StrictBenchmarkModel):
    prompt_tokens: Literal[
        "ordinary input price unless provider usage separately reports cached tokens"
    ]
    completion_tokens: Literal["output price"]
    billing_claim: Literal["estimated list-price cost, not an invoice"]


class PriceSource(StrictBenchmarkModel):
    url: str = Field(pattern=r"^https://.+$")
    retrieved_at: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    utf8_bytes: int = Field(ge=1)
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


class PricingLock(StrictBenchmarkModel):
    schema_version: Literal["1.0"]
    provider: Literal["Z.AI"]
    model: str = Field(pattern=r"^[A-Za-z0-9._-]{1,100}$")
    currency: Literal["USD"]
    unit_tokens: Literal[1_000_000]
    prices: PriceValues
    cost_method: CostMethod
    source: PriceSource


@dataclass(frozen=True)
class PricingPolicy:
    input_usd_per_million: float | None
    output_usd_per_million: float | None
    provenance: RepairCostProvenance

    def estimate(self, prompt_tokens: int, completion_tokens: int) -> float | None:
        if self.input_usd_per_million is None or self.output_usd_per_million is None:
            return None
        return (
            prompt_tokens * self.input_usd_per_million
            + completion_tokens * self.output_usd_per_million
        ) / 1_000_000


class SafeCLIError(RuntimeError):
    """Expected CLI failure whose message contains no external content."""


class ModelResponseError(ValueError):
    """Fail-closed model response rejection with no response echo."""


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _reject_constant(_value: str) -> None:
    raise ModelResponseError("model response contains a non-JSON number")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ModelResponseError("model response contains a duplicate object key")
        value[key] = item
    return value


def parse_model_patch(content: str) -> ModelPatchPayload:
    """Accept exactly one JSON object; reject fences, prose, duplicates, and extra fields."""

    if not isinstance(content, str):
        raise ModelResponseError("model response is not text")
    try:
        encoded = content.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise ModelResponseError("model response is not valid UTF-8 text") from None
    if not encoded or len(encoded) > 30_000_000:
        raise ModelResponseError("model response has an invalid byte length")
    stripped = content.strip()
    if not stripped.startswith("{") or not stripped.endswith("}"):
        raise ModelResponseError("model response must be one bare JSON object")
    try:
        value = json.loads(
            stripped,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
        return ModelPatchPayload.model_validate(value)
    except (json.JSONDecodeError, UnicodeError, ValidationError, ModelResponseError):
        raise ModelResponseError("model response failed strict JSON validation") from None


def _request_prompt(request: PatchRequest) -> str:
    return json.dumps(
        request.model_dump(mode="json"),
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _validated_usage(result: CompletionResult) -> tuple[int, int]:
    prompt = result.prompt_tokens
    completion = result.completion_tokens
    total = result.total_tokens
    if type(prompt) is not int or prompt < 0:  # bool is not valid token evidence
        raise PatchProviderError("provider usage is unavailable")
    if type(completion) is not int or completion < 0:
        raise PatchProviderError("provider usage is unavailable")
    if total is not None and (type(total) is not int or total != prompt + completion):
        raise PatchProviderError("provider usage is inconsistent")
    return prompt, completion


class LLMPatchProvider:
    """Synchronous executor adapter backed by ``LLMClient.complete_with_usage``."""

    def __init__(
        self,
        client: CompletionClient,
        *,
        pricing: PricingPolicy,
        model: str | None,
        temperature: float,
        timeout_seconds: float,
        max_retries: int,
    ) -> None:
        if not 0 <= temperature <= 2:
            raise ValueError("temperature must be between 0 and 2")
        if not 1 <= timeout_seconds <= 3_600:
            raise ValueError("timeout must be between 1 and 3600 seconds")
        if not 0 <= max_retries <= 5:
            raise ValueError("max retries must be between 0 and 5")
        self.client = client
        self.pricing = pricing
        self.model = model
        self.temperature = temperature
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries

    def __call__(self, request: PatchRequest) -> PatchProposal:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            pass
        else:
            raise PatchProviderError("provider adapter requires a synchronous caller")
        return asyncio.run(self._complete(request))

    async def _complete(self, request: PatchRequest) -> PatchProposal:
        result: CompletionResult | None = None
        for attempt in range(self.max_retries + 1):
            try:
                result = await asyncio.wait_for(
                    self.client.complete_with_usage(
                        _request_prompt(request),
                        model=self.model,
                        temperature=self.temperature,
                        system=SYSTEM_PROMPT,
                    ),
                    timeout=self.timeout_seconds,
                )
            except Exception:
                if attempt < self.max_retries:
                    continue
                raise PatchProviderError("model completion failed") from None
            break
        if result is None:  # defensive: the bounded loop always assigns or raises
            raise PatchProviderError("model completion failed")
        prompt_tokens, completion_tokens = _validated_usage(result)
        cost = self.pricing.estimate(prompt_tokens, completion_tokens)
        try:
            payload = parse_model_patch(result.content)
        except ModelResponseError:
            raise PatchProviderError(
                "model response was rejected",
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                estimated_cost_usd=cost,
                human_intervention=False,
            ) from None
        # Usage, price, and intervention fields are created here from trusted
        # adapter state.  The model schema has no fields with which to claim them.
        return PatchProposal(
            replacements=payload.replacements,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            estimated_cost_usd=cost,
            human_intervention=False,
        )


def load_pricing_lock(path: Path, *, root: Path, model: str) -> tuple[PricingLock, str, str]:
    root = root.resolve()
    requested = path.absolute()
    if requested.is_symlink():
        raise SafeCLIError("pricing lock validation failed")
    resolved = requested.resolve()
    if root not in resolved.parents or not resolved.is_file():
        raise SafeCLIError("pricing lock validation failed")
    payload = resolved.read_bytes()
    if not payload or len(payload) > 100_000:
        raise SafeCLIError("pricing lock validation failed")
    try:
        lock = PricingLock.model_validate(yaml.safe_load(payload.decode("utf-8")))
    except (UnicodeDecodeError, ValidationError, yaml.YAMLError):
        raise SafeCLIError("pricing lock validation failed") from None
    if lock.model != model:
        raise SafeCLIError("pricing lock model does not match the selected model")
    relative = resolved.relative_to(root).as_posix()
    return lock, relative, _sha256(payload)


def build_pricing_policy(
    *,
    root: Path,
    model: str,
    pricing_lock: Path | None,
    input_usd_per_million: float | None,
    output_usd_per_million: float | None,
) -> PricingPolicy:
    if (input_usd_per_million is None) != (output_usd_per_million is None):
        raise SafeCLIError("input and output prices must be provided together")
    for value in (input_usd_per_million, output_usd_per_million):
        if value is not None and (not math.isfinite(value) or value < 0):
            raise SafeCLIError("explicit prices must be finite and nonnegative")
    lock: PricingLock | None = None
    lock_path: str | None = None
    lock_sha256: str | None = None
    if pricing_lock is not None:
        lock, lock_path, lock_sha256 = load_pricing_lock(
            pricing_lock,
            root=root,
            model=model,
        )
    explicit = input_usd_per_million is not None
    if explicit:
        input_rate = input_usd_per_million
        output_rate = output_usd_per_million
        rate_source: Literal["pricing-lock", "cli-explicit", "cli-override"] = (
            "cli-override" if lock is not None else "cli-explicit"
        )
    elif lock is not None:
        input_rate = lock.prices.input
        output_rate = lock.prices.output
        rate_source = "pricing-lock"
    else:
        provenance = RepairCostProvenance(
            rate_source="unpriced",
            model=model,
            input_usd_per_million=None,
            output_usd_per_million=None,
            cached_input_usd_per_million=None,
            cached_input_tokens_reported=False,
            prompt_token_cost_method="unpriced",
            billing_claim="unpriced",
        )
        return PricingPolicy(None, None, provenance)
    assert input_rate is not None and output_rate is not None
    provenance = RepairCostProvenance(
        rate_source=rate_source,
        model=model,
        input_usd_per_million=input_rate,
        output_usd_per_million=output_rate,
        cached_input_usd_per_million=lock.prices.cached_input if lock is not None else None,
        cached_input_tokens_reported=False,
        prompt_token_cost_method="ordinary-input-rate-no-cached-breakdown",
        billing_claim=(
            "estimated-list-price-not-invoice"
            if rate_source == "pricing-lock"
            else "estimated-configured-rate-cost-not-invoice"
        ),
        pricing_lock_path=lock_path,
        pricing_lock_sha256=lock_sha256,
        source_url=lock.source.url if lock is not None else None,
        source_retrieved_at=lock.source.retrieved_at if lock is not None else None,
        source_utf8_bytes=lock.source.utf8_bytes if lock is not None else None,
        source_sha256=lock.source.sha256 if lock is not None else None,
    )
    return PricingPolicy(input_rate, output_rate, provenance)


def validate_cost_claims(report: RepairBenchmarkReport, pricing: PricingPolicy) -> list[str]:
    errors: list[str] = []
    if report.cost_provenance != pricing.provenance:
        errors.append("report cost provenance does not match the configured policy")
    for result in report.results:
        expected = pricing.estimate(result.prompt_tokens, result.completion_tokens)
        actual = result.estimated_cost_usd
        if actual is None:
            if expected is not None and (
                result.execution_status == "executed"
                or result.prompt_tokens + result.completion_tokens > 0
            ):
                errors.append(f"{result.task_id}: measured usage lacks an estimated cost")
            continue
        if expected is None or not math.isclose(actual, expected, rel_tol=1e-12, abs_tol=1e-15):
            errors.append(f"{result.task_id}: estimated cost does not match measured usage")
    return errors


def _bounded_float(minimum: float, maximum: float) -> Callable[[str], float]:
    def parse(value: str) -> float:
        try:
            parsed = float(value)
        except ValueError as exc:
            raise argparse.ArgumentTypeError("value must be numeric") from exc
        if not math.isfinite(parsed) or not minimum <= parsed <= maximum:
            raise argparse.ArgumentTypeError(f"value must be between {minimum} and {maximum}")
        return parsed

    return parse


def _bounded_integer(minimum: int, maximum: int) -> Callable[[str], int]:
    def parse(value: str) -> int:
        try:
            parsed = int(value)
        except ValueError as exc:
            raise argparse.ArgumentTypeError("value must be an integer") from exc
        if not minimum <= parsed <= maximum:
            raise argparse.ArgumentTypeError(f"value must be between {minimum} and {maximum}")
        return parsed

    return parse


def build_parser(*, root: Path = ROOT) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the fixed DevFlow repair benchmark")
    parser.add_argument(
        "--manifest",
        type=Path,
        default=root / "benchmarks/repository_repair/tasks.yaml",
    )
    parser.add_argument(
        "--repos-root",
        type=Path,
        default=root / ".devflow/benchmark-repos",
    )
    parser.add_argument(
        "--checkpoint",
        type=Path,
        default=root / ".devflow/benchmarks/repository-repair-agent.json",
    )
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--task-id", action="append", default=[])
    parser.add_argument("--model", help="Model id; defaults to LLM_MODEL/client default")
    parser.add_argument("--temperature", type=_bounded_float(0, 2), default=0.0)
    parser.add_argument("--timeout", type=_bounded_float(1, 3_600), default=300.0)
    parser.add_argument("--max-retries", type=_bounded_integer(0, 5), default=2)
    parser.add_argument("--pricing-lock", type=Path)
    parser.add_argument(
        "--input-usd-per-million",
        type=_bounded_float(0, 1_000_000),
    )
    parser.add_argument(
        "--output-usd-per-million",
        type=_bounded_float(0, 1_000_000),
    )
    parser.add_argument("--python", type=Path, default=Path(sys.executable))
    parser.add_argument("--temp-root", type=Path)
    parser.add_argument("--run-id")
    return parser


ClientFactory = Callable[[str | None], CompletionClient]
Executor = Callable[..., RepairBenchmarkReport]


def _client_factory(model: str | None) -> CompletionClient:
    return cast(CompletionClient, LLMClient(default_model=model))


def run_cli(
    args: argparse.Namespace,
    *,
    root: Path = ROOT,
    client_factory: ClientFactory = _client_factory,
    executor: Executor = execute_repair_benchmark,
) -> int:
    api_key = os.getenv("LLM_API_KEY")
    if not api_key or not api_key.strip():
        raise SafeCLIError("LLM_API_KEY is required in the process environment")
    if args.resume and not args.checkpoint.is_file():
        raise SafeCLIError("resume checkpoint is unavailable")
    if args.checkpoint.absolute().is_symlink():
        raise SafeCLIError("checkpoint path cannot be a symlink")
    if not args.python.resolve().is_file():
        raise SafeCLIError("selected Python executable is unavailable")
    try:
        manifest: RepairBenchmarkManifest = load_repair_manifest(args.manifest.resolve())
    except Exception:
        raise SafeCLIError("repair manifest validation failed") from None
    try:
        manifest_errors = validate_repair_manifest(manifest, args.repos_root.resolve())
    except Exception:
        raise SafeCLIError("manifest/source validation failed") from None
    if manifest_errors:
        raise SafeCLIError(f"manifest/source validation failed ({len(manifest_errors)} errors)")
    try:
        client = client_factory(args.model)
    except Exception:
        raise SafeCLIError("model client configuration failed") from None
    effective_model = args.model or client.default_model
    if not isinstance(effective_model, str) or (
        re.fullmatch(r"[A-Za-z0-9._-]{1,100}", effective_model) is None
    ):
        raise SafeCLIError("selected model id is invalid")
    pricing = build_pricing_policy(
        root=root,
        model=effective_model,
        pricing_lock=args.pricing_lock,
        input_usd_per_million=args.input_usd_per_million,
        output_usd_per_million=args.output_usd_per_million,
    )
    provider = LLMPatchProvider(
        client,
        pricing=pricing,
        model=args.model,
        temperature=args.temperature,
        timeout_seconds=args.timeout,
        max_retries=args.max_retries,
    )
    try:
        resume = load_repair_report(args.checkpoint) if args.resume else None
    except Exception:
        raise SafeCLIError("resume checkpoint validation failed") from None
    try:
        report = executor(
            manifest,
            repos_root=args.repos_root.resolve(),
            provider=provider,
            task_ids=args.task_id or None,
            executables={name: args.python.resolve() for name in manifest.repositories},
            temp_root=args.temp_root,
            resume_report=resume,
            checkpoint_path=args.checkpoint,
            run_id=args.run_id,
            cost_provenance=pricing.provenance,
        )
    except Exception:
        raise SafeCLIError("repair benchmark execution failed") from None
    report_errors = [
        *validate_repair_report(report, manifest),
        *validate_cost_claims(report, pricing),
    ]
    if report_errors:
        raise SafeCLIError(f"report validation failed ({len(report_errors)} errors)")
    try:
        persisted = load_repair_report(args.checkpoint)
    except Exception:
        raise SafeCLIError("persisted report validation failed") from None
    if persisted != report:
        raise SafeCLIError("persisted report does not match the completed report")
    summary = report.summary.model_dump(mode="json")
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    print(f"report={args.checkpoint.resolve()}")
    print(f"report_sha256={report.report_sha256}")
    return 0


def _contains_forbidden_secret_option(arguments: Sequence[str]) -> bool:
    forbidden = {
        "--api-key",
        "--base-url",
        "--llm-api-key",
        "--llm-base-url",
    }
    return any(argument.split("=", 1)[0].casefold() in forbidden for argument in arguments)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if _contains_forbidden_secret_option(arguments):
        print("error: credentials and base URLs are environment-only", file=sys.stderr)
        return 2
    args = build_parser().parse_args(arguments)
    try:
        return run_cli(args)
    except SafeCLIError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "LLMPatchProvider",
    "ModelPatchPayload",
    "ModelResponseError",
    "PricingLock",
    "PricingPolicy",
    "SafeCLIError",
    "SYSTEM_PROMPT",
    "build_parser",
    "build_pricing_policy",
    "load_pricing_lock",
    "main",
    "parse_model_patch",
    "run_cli",
    "validate_cost_claims",
]
