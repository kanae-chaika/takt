import { createHash, randomUUID } from 'node:crypto';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  utimesSync,
  writeFileSync,
} from 'node:fs';
import { open } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { basename, join, resolve, sep } from 'node:path';
import { StringDecoder } from 'node:string_decoder';
import { spawnManagedProcess } from '../../shared/utils/spawn.js';

const require = createRequire(import.meta.url);

const QUINT_TIMEOUT_MS = 60_000;
const ALLOY_VERSION = '6.2.0';
const ALLOY_JAR_URL = `https://repo1.maven.org/maven2/org/alloytools/org.alloytools.alloy.dist/${ALLOY_VERSION}/org.alloytools.alloy.dist-${ALLOY_VERSION}.jar`;
const ALLOY_JAR_SHA256 = '6037cbeee0e8423c1c468447ed10f5fcf2f2743a2ffc39cb1c81f2905c0fdb9d';
const MAX_PROCESS_OUTPUT = 1024 * 1024;
const ALLOY_COMMAND_OUTPUT_TRUNCATED_MESSAGE = 'Alloy command enumeration output was truncated before all commands could be read.';
const MAX_FAILURE_MESSAGE = 8_000;
const QUINT_PARSE_READ_BUFFER_SIZE = 64 * 1024;
const MAX_RETAINED_PARSE_TEXT = MAX_FAILURE_MESSAGE + 1;
const MAX_RETAINED_PARSE_NUMBER_DIGITS = 1_200;
const OUTPUT_TRUNCATED_SUFFIX = '\n[output truncated]';
const QUINT_INVARIANT_NAME_TRUNCATED_SUFFIX = '… [invariant name truncated]';
const JSON_STRING_ESCAPES: Readonly<Record<string, string>> = {
  '"': '"',
  '\\': '\\',
  '/': '/',
  b: '\b',
  f: '\f',
  n: '\n',
  r: '\r',
  t: '\t',
};
const TLC_TIMEOUT_GUIDANCE = 'TLC exhaustively explores the entire state space; --max-steps does not limit TLC. Bound all state variables, especially int variables, to finite ranges.';
const TLC_OUTPUT_TRUNCATED_MESSAGE = 'TLC output was truncated at the capture limit; diagnostics may be missing.';
// Each bounded process refreshes the workspace timestamp, so cleanup measures
// inactivity rather than the total duration of sequential verification stages.
const STALE_VERIFY_RUN_MAX_AGE_MS = 60 * 60 * 1000;

export type FormalSpecVerificationStatus = 'passed' | 'failed' | 'error' | 'skipped';

export interface FormalSpecStageResult {
  readonly status: FormalSpecVerificationStatus;
  readonly message?: string;
  readonly checks?: readonly number[];
}

export interface FormalSpecQuintResult extends FormalSpecStageResult {
  readonly parse?: FormalSpecStageResult;
  readonly typecheck?: FormalSpecStageResult;
  readonly run?: FormalSpecStageResult;
  readonly verify?: FormalSpecStageResult;
  readonly invariants?: readonly string[];
  readonly temporal?: readonly string[];
}

export interface FormalSpecAlloyResult extends FormalSpecStageResult {
  readonly commands?: readonly AlloyParsedCommand[];
}

export interface FormalSpecVerificationResult {
  readonly verdict: 'passed' | 'failed' | 'error';
  readonly verificationStarted: boolean;
  readonly message?: string;
  readonly javaMajorVersion?: number;
  readonly quint: FormalSpecQuintResult;
  readonly alloy: FormalSpecAlloyResult;
}

export interface FormalSpecVerificationOptions {
  readonly abortSignal?: AbortSignal;
  readonly modelCheckTimeoutSeconds: number;
}

export interface FormalSpecBlocks {
  readonly quint: readonly string[];
  readonly alloy: readonly string[];
}

export interface QuintVerificationTargets {
  readonly invariants: readonly QuintVerificationTarget[];
  readonly temporal: readonly QuintVerificationTarget[];
}

export interface QuintVerificationTarget {
  readonly moduleName: string;
  readonly name: string;
}

export interface AlloyParsedCommand {
  readonly number: number;
  readonly type: string;
  readonly label: string;
}

type ProcessOutcome = 'exit' | 'spawn_error' | 'timeout' | 'signal';
type QuintVerificationBackend = 'typescript' | 'apalache' | 'tlc';

interface ProcessResult {
  readonly outcome: ProcessOutcome;
  readonly status: number | null;
  readonly stdout: string;
  readonly stderr: string;
  readonly stdoutTruncated: boolean;
  readonly stderrTruncated: boolean;
  readonly error?: string;
}

interface FenceState {
  readonly character: '`' | '~';
  readonly length: number;
  readonly target?: 'quint' | 'alloy';
  readonly content: string[];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function parseFenceLine(line: string): { character: '`' | '~'; length: number; info: string } | undefined {
  const match = /^( {0,3})(`{3,}|~{3,})(.*)$/u.exec(line);
  if (!match) {
    return undefined;
  }

  const marker = match[2];
  if (!marker) {
    return undefined;
  }
  const character = marker[0];
  if (character !== '`' && character !== '~') {
    return undefined;
  }
  return {
    character,
    length: marker.length,
    info: (match[3] ?? '').trim(),
  };
}

/** Extract only closed Quint and Alloy fences from one provider response. */
export function extractFormalSpecBlocks(response: string): FormalSpecBlocks {
  const blocks: { quint: string[]; alloy: string[] } = { quint: [], alloy: [] };
  let fence: FenceState | undefined;

  for (const line of response.split(/\r\n?|\n/u)) {
    const parsedFence = parseFenceLine(line);

    if (fence) {
      const closesFence = parsedFence !== undefined
        && parsedFence.character === fence.character
        && parsedFence.length >= fence.length
        && parsedFence.info === '';
      if (closesFence) {
        if (fence.target) {
          blocks[fence.target].push(fence.content.join('\n').trim());
        }
        fence = undefined;
      } else if (fence.target) {
        fence.content.push(line);
      }
      continue;
    }

    if (!parsedFence) {
      continue;
    }

    const normalizedInfo = parsedFence.info.toLowerCase();
    const target = normalizedInfo === 'quint' || normalizedInfo === 'alloy'
      ? normalizedInfo
      : undefined;
    fence = {
      character: parsedFence.character,
      length: parsedFence.length,
      ...(target ? { target } : {}),
      content: [],
    };
  }

  if (fence?.target) {
    throw new Error(`Unclosed ${fence.target} code fence`);
  }

  return blocks;
}

/** Parse the Java version strings emitted by common JDK distributions. */
export function detectJavaMajorVersion(output: string): number | undefined {
  const versionMatch = /\bversion\s+["']?(\d+)(?:\.(\d+))?/iu.exec(output);
  const directMatch = /\b(?:openjdk|java)\s+["']?(\d+)(?:\.(\d+))?/iu.exec(output);
  const match = versionMatch ?? directMatch;
  if (!match) {
    return undefined;
  }

  const first = Number.parseInt(match[1] ?? '', 10);
  if (!Number.isInteger(first)) {
    return undefined;
  }
  if (first === 1) {
    const legacyMinor = Number.parseInt(match[2] ?? '', 10);
    return Number.isInteger(legacyMinor) ? legacyMinor : undefined;
  }
  return first;
}

/** Select every conventionally named Quint invariant and temporal property. */
export function selectQuintVerificationTargets(parseResult: unknown): QuintVerificationTargets {
  const invariants: QuintVerificationTarget[] = [];
  const temporal: QuintVerificationTarget[] = [];
  if (!isRecord(parseResult) || !Array.isArray(parseResult.modules)) {
    return { invariants, temporal };
  }

  for (const module of parseResult.modules) {
    if (!isRecord(module) || typeof module.name !== 'string' || !Array.isArray(module.declarations)) {
      continue;
    }
    for (const declaration of module.declarations) {
      if (!isRecord(declaration) || declaration.kind !== 'def' || typeof declaration.name !== 'string') {
        continue;
      }
      if (declaration.qualifier === 'val' && declaration.name.startsWith('inv')) {
        invariants.push({ moduleName: module.name, name: declaration.name });
      }
      if (declaration.qualifier === 'temporal' && declaration.name.startsWith('prop')) {
        temporal.push({ moduleName: module.name, name: declaration.name });
      }
    }
  }

  return { invariants, temporal };
}

const QUINT_MAIN_REQUIRED_MESSAGE = 'Quint verification requires a module with action init and action step.';

function formatQuintTarget(target: QuintVerificationTarget): string {
  return `${target.moduleName}::${target.name}`;
}

function quintTargetsOutsideMainModule(
  targets: QuintVerificationTargets,
  mainModule: string,
): QuintVerificationTarget[] {
  return [...targets.invariants, ...targets.temporal]
    .filter((target) => target.moduleName !== mainModule);
}

function quintTargetScopeError(
  targets: QuintVerificationTargets,
  mainModule: string,
): string | undefined {
  const outOfScopeTargets = quintTargetsOutsideMainModule(targets, mainModule);
  if (outOfScopeTargets.length === 0) {
    return undefined;
  }
  return `Quint verification targets must be declared in the main module ${mainModule}: ${outOfScopeTargets.map(formatQuintTarget).join(', ')}.`;
}

function selectQuintMainModule(parseResult: unknown): string | undefined {
  if (!isRecord(parseResult) || !Array.isArray(parseResult.modules)) {
    return undefined;
  }

  for (const module of parseResult.modules) {
    if (!isRecord(module) || typeof module.name !== 'string' || !Array.isArray(module.declarations)) {
      continue;
    }

    const actionNames = new Set(
      module.declarations
        .filter((declaration): declaration is Record<string, unknown> => (
          isRecord(declaration)
          && declaration.kind === 'def'
          && declaration.qualifier === 'action'
          && typeof declaration.name === 'string'
        ))
        .map((declaration) => declaration.name),
    );
    if (actionNames.has('init') && actionNames.has('step')) {
      return module.name;
    }
  }

  return undefined;
}

/** Return all parsed Alloy checks, including repeated command numbers. */
export function selectAlloyCheckTargets(commands: readonly AlloyParsedCommand[]): readonly number[] {
  return commands
    .filter((command) => command.type === 'check')
    .map((command) => command.number);
}

function toProcessText(value: string | Buffer | null): string {
  return value === null ? '' : String(value);
}

function appendProcessOutput(current: string, chunk: string): { output: string; truncated: boolean } {
  const remaining = MAX_PROCESS_OUTPUT - current.length;
  return {
    output: remaining > 0 ? current + chunk.slice(0, remaining) : current,
    truncated: chunk.length > Math.max(remaining, 0),
  };
}

const TLC_ERROR_LINE_PATTERN = /^\s*Error:/u;
const TLC_FAILURE_LINE_PATTERN = /^\s*\[failure\]/u;
const ANSI_ESCAPE_PATTERN = new RegExp(`${String.fromCharCode(27)}\\[[0-?]*[ -/]*[@-~]`, 'gu');
const QUINT_VIOLATION_HEADER = '[violation] Found an issue';
const QUINT_VIOLATION_HEADER_PATTERN = /^\[violation\]\s+Found an issue(?:\s|$)/u;
const QUINT_VIOLATION_HEADER_PREFIX_PATTERN = /^\[violation\]\s+Found an issue\s/u;
const QUINT_VIOLATION_MARKER = '❌';
const QUINT_VIOLATION_NAME_PATTERN = /^❌\s+(.+?)\s*$/u;
const QUINT_VIOLATION_TERMINAL = 'Use --verbosity=3 to show executions.';

function extractTlcDiagnostics(output: string): string | undefined {
  const lines = output
    .replace(ANSI_ESCAPE_PATTERN, '')
    .split(/\r\n?|\n/u);
  const startIndex = lines.findIndex((line) => TLC_ERROR_LINE_PATTERN.test(line));
  if (startIndex < 0) {
    return undefined;
  }

  const failureIndex = lines.findIndex((line, index) => (
    index >= startIndex && TLC_FAILURE_LINE_PATTERN.test(line)
  ));
  const endIndex = failureIndex >= 0 ? failureIndex + 1 : lines.length;
  return lines
    .slice(startIndex, endIndex)
    .join('\n')
    .trim();
}

async function runProcess(
  command: string,
  args: readonly string[],
  cwd: string,
  timeout: number,
  abortSignal?: AbortSignal,
  onStdoutChunk?: (chunk: string) => void,
): Promise<ProcessResult> {
  abortSignal?.throwIfAborted();
  const now = new Date();
  utimesSync(cwd, now, now);
  const processAbortController = new AbortController();
  let timedOut = false;
  let stdout = '';
  let stderr = '';
  let stdoutTruncated = false;
  let stderrTruncated = false;
  const timeoutHandle = setTimeout(() => {
    timedOut = true;
    processAbortController.abort(new Error(`Process timed out after ${timeout} ms`));
  }, timeout);
  const onAbort = (): void => {
    processAbortController.abort(abortSignal?.reason);
  };
  abortSignal?.addEventListener('abort', onAbort, { once: true });

  try {
    // A partially spawned process is killed with its tree through the abort
    // contract of spawnManagedProcess.
    const managedProcess = spawnManagedProcess(
      command,
      args,
      {
        cwd,
        env: {
          ...process.env,
          TMPDIR: cwd,
          TMP: cwd,
          TEMP: cwd,
        },
        stdio: ['ignore', 'pipe', 'pipe'],
      },
      processAbortController.signal,
    );
    managedProcess.child.stdout?.setEncoding('utf8');
    managedProcess.child.stdout?.on('data', (chunk: string | Buffer) => {
      const text = toProcessText(chunk);
      onStdoutChunk?.(text);
      const appended = appendProcessOutput(stdout, text);
      stdout = appended.output;
      stdoutTruncated ||= appended.truncated;
    });
    managedProcess.child.stderr?.setEncoding('utf8');
    managedProcess.child.stderr?.on('data', (chunk: string | Buffer) => {
      const appended = appendProcessOutput(stderr, toProcessText(chunk));
      stderr = appended.output;
      stderrTruncated ||= appended.truncated;
    });

    const exit = await managedProcess.wait();
    abortSignal?.throwIfAborted();
    if (timedOut) {
      return {
        outcome: 'timeout',
        status: null,
        stdout,
        stderr,
        stdoutTruncated,
        stderrTruncated,
        error: `Process timed out after ${timeout} ms`,
      };
    }
    return {
      outcome: exit.signal === null ? 'exit' : 'signal',
      status: exit.code,
      stdout,
      stderr,
      stdoutTruncated,
      stderrTruncated,
    };
  } catch (error) {
    abortSignal?.throwIfAborted();
    if (timedOut) {
      return {
        outcome: 'timeout',
        status: null,
        stdout,
        stderr,
        stdoutTruncated,
        stderrTruncated,
        error: `Process timed out after ${timeout} ms`,
      };
    }
    return {
      outcome: 'spawn_error',
      status: null,
      stdout,
      stderr,
      stdoutTruncated,
      stderrTruncated,
      error: error instanceof Error ? error.message : String(error),
    };
  } finally {
    clearTimeout(timeoutHandle);
    abortSignal?.removeEventListener('abort', onAbort);
  }
}

function rawProcessOutput(result: ProcessResult): string {
  return [result.stderr.trim(), result.stdout.trim()]
    .filter((detail) => detail.length > 0)
    .join('\n');
}

function formatProcessFailureMessage(
  result: ProcessResult,
  output: string,
  additionalMessage?: string,
): string {
  const details = [additionalMessage, result.error, output]
    .filter((detail): detail is string => detail !== undefined && detail.length > 0)
    .join('\n');
  const exitStatus = result.status === null ? 'unknown' : String(result.status);
  const defaultMessage = result.outcome === 'signal'
    ? 'Process was terminated by a signal.'
    : result.outcome === 'timeout'
      ? 'Process timed out.'
      : `Process exited with status ${exitStatus}`;
  const message = details || defaultMessage;
  return message.length > MAX_FAILURE_MESSAGE
    ? `${message.slice(0, MAX_FAILURE_MESSAGE - OUTPUT_TRUNCATED_SUFFIX.length)}${OUTPUT_TRUNCATED_SUFFIX}`
    : message;
}

function processFailureMessage(result: ProcessResult): string {
  return formatProcessFailureMessage(result, rawProcessOutput(result));
}

interface StreamedJsonString {
  readonly prefix: string;
  readonly prefixComplete: boolean;
  readonly length: number;
  readonly basename: string;
  readonly basenameComplete: boolean;
  readonly basenameLength: number;
}

class JsonStringCapture {
  private prefix = '';
  private length = 0;
  private currentPathPart = '';
  private currentPathPartLength = 0;
  private previousPathPart = '';
  private previousPathPartLength = 0;

  constructor(
    private readonly limit: number,
    private readonly captureContent: boolean,
    private readonly capturePath: boolean,
  ) {}

  append(character: string): void {
    this.length = Math.min(this.limit + 1, this.length + 1);
    if (this.captureContent && this.prefix.length < this.limit) {
      this.prefix += character;
    }

    if (!this.capturePath) {
      return;
    }
    if (character === sep) {
      if (this.currentPathPartLength > 0) {
        this.previousPathPart = this.currentPathPart;
        this.previousPathPartLength = this.currentPathPartLength;
      }
      this.currentPathPart = '';
      this.currentPathPartLength = 0;
      return;
    }

    this.currentPathPartLength = Math.min(this.limit + 1, this.currentPathPartLength + 1);
    if (this.currentPathPart.length < this.limit) {
      this.currentPathPart += character;
    }
  }

  finish(): StreamedJsonString {
    let pathPart: string;
    let pathPartLength: number;
    if (this.length <= this.limit) {
      pathPart = basename(this.prefix);
      pathPartLength = pathPart.length;
    } else if (this.currentPathPartLength > 0) {
      pathPart = this.currentPathPart;
      pathPartLength = this.currentPathPartLength;
    } else {
      pathPart = this.previousPathPart;
      pathPartLength = this.previousPathPartLength;
    }

    return {
      prefix: this.prefix,
      prefixComplete: this.length <= this.limit,
      length: this.length,
      basename: pathPart,
      basenameComplete: pathPartLength <= pathPart.length,
      basenameLength: pathPartLength,
    };
  }
}

class BoundedParseText {
  text = '';
  length = 0;
  complete = true;

  append(value: string, actualLength = value.length, valueComplete = true): void {
    const available = MAX_RETAINED_PARSE_TEXT - this.text.length;
    if (available > 0) {
      this.text += value.slice(0, available);
    }
    this.length = Math.min(MAX_RETAINED_PARSE_TEXT, this.length + actualLength);
    if (!valueComplete || actualLength > value.length || this.length > MAX_FAILURE_MESSAGE) {
      this.complete = false;
    }
  }
}

interface ParseDiagnosticCandidate {
  readonly text: string;
  readonly complete: boolean;
  readonly prefixLength: number;
  readonly truncatedLocations?: {
    readonly positions: string;
    readonly positionEnds: readonly number[];
    readonly firstPosition: string;
    readonly explanation: string;
  };
}

interface ParseErrorsCollector {
  invalid: boolean;
  count: bigint;
  candidates: ParseDiagnosticCandidate[];
  retainingCandidates: boolean;
}

interface ParseLocationsCollector {
  invalid: boolean;
  count: number;
  readonly text: BoundedParseText;
  readonly positionEnds: number[];
  firstPosition?: BoundedParseText;
}

interface ParsePositionBuilder {
  line?: number;
  col?: number;
}

interface ParseLocationBuilder {
  source?: StreamedJsonString;
  start?: ParsePositionBuilder;
  readonly locations: ParseLocationsCollector;
}

interface ParseDiagnosticBuilder {
  explanation?: StreamedJsonString;
  locations?: ParseLocationsCollector;
  readonly errors: ParseErrorsCollector;
}

interface ParseRootBuilder {
  errorsSeen: boolean;
  errorsIsArray: boolean;
  errors?: ParseErrorsCollector;
}

type JsonRole = 'root' | 'errors' | 'diagnostic' | 'locations' | 'location' | 'position' | 'other';
type JsonFrameState = 'keyOrEnd' | 'key' | 'colon' | 'value' | 'valueOrEnd' | 'commaOrEnd';

type JsonValueTarget =
  | { readonly kind: 'root' }
  | { readonly kind: 'rootErrors'; readonly root: ParseRootBuilder }
  | { readonly kind: 'diagnosticElement'; readonly errors: ParseErrorsCollector }
  | { readonly kind: 'diagnosticExplanation'; readonly diagnostic: ParseDiagnosticBuilder }
  | { readonly kind: 'diagnosticLocations'; readonly diagnostic: ParseDiagnosticBuilder }
  | { readonly kind: 'locationElement'; readonly locations: ParseLocationsCollector }
  | { readonly kind: 'locationSource'; readonly location: ParseLocationBuilder }
  | { readonly kind: 'locationStart'; readonly location: ParseLocationBuilder }
  | { readonly kind: 'positionLine'; readonly position: ParsePositionBuilder }
  | { readonly kind: 'positionColumn'; readonly position: ParsePositionBuilder }
  | { readonly kind: 'other' };

interface JsonContainerFrame {
  readonly kind: 'object' | 'array';
  readonly role: JsonRole;
  readonly data?: ParseRootBuilder | ParseErrorsCollector | ParseDiagnosticBuilder | ParseLocationsCollector | ParseLocationBuilder | ParsePositionBuilder;
  state: JsonFrameState;
  key?: string;
}

type JsonNumberState =
  | 'start'
  | 'afterMinus'
  | 'zero'
  | 'integer'
  | 'fractionStart'
  | 'fraction'
  | 'exponentStart'
  | 'exponentSign'
  | 'exponentDigits';

class JsonNumberCapture {
  private raw = '';
  private rawLength = 0;
  private negative = false;
  private exponentNegative = false;
  private exponentMagnitude = 0;
  private fractionDigits = 0;
  private hasSignificantDigit = false;
  private significantDigits = 0;
  private significantPrefix = '';
  private omittedSignificantDigit = false;
  private omittedNonZeroDigit = false;

  append(character: string, previousState: JsonNumberState): void {
    this.rawLength = Math.min(2_049, this.rawLength + 1);
    if (this.raw.length < 2_048) {
      this.raw += character;
    }

    if (previousState === 'start' && character === '-') {
      this.negative = true;
      return;
    }
    if ((previousState === 'exponentStart' || previousState === 'exponentSign')
      && (character === '-' || character === '+')) {
      this.exponentNegative = character === '-';
      return;
    }
    if ((previousState === 'exponentStart' || previousState === 'exponentSign' || previousState === 'exponentDigits')
      && character >= '0' && character <= '9') {
      this.exponentMagnitude = Math.min(1_000_000_000, this.exponentMagnitude * 10 + Number(character));
      return;
    }
    if (!['start', 'afterMinus', 'zero', 'integer', 'fractionStart', 'fraction'].includes(previousState)
      || character < '0'
      || character > '9') {
      return;
    }

    if (previousState === 'fractionStart' || previousState === 'fraction') {
      this.fractionDigits += 1;
    }
    const digit = Number(character);
    if (!this.hasSignificantDigit && digit === 0) {
      return;
    }
    this.hasSignificantDigit = true;
    this.significantDigits += 1;
    if (this.significantPrefix.length < MAX_RETAINED_PARSE_NUMBER_DIGITS) {
      this.significantPrefix += character;
    } else {
      this.omittedSignificantDigit = true;
      this.omittedNonZeroDigit ||= digit !== 0;
    }
  }

  toNumber(): number {
    if (this.rawLength <= this.raw.length) {
      return Number(this.raw);
    }
    if (!this.hasSignificantDigit) {
      return this.negative ? -0 : 0;
    }

    let mantissa = this.significantPrefix;
    let power = (this.exponentNegative ? -this.exponentMagnitude : this.exponentMagnitude)
      - this.fractionDigits
      + (this.significantDigits - mantissa.length);
    if (this.omittedSignificantDigit && this.omittedNonZeroDigit) {
      mantissa += '1';
      power -= 1;
    }
    return Number(`${this.negative ? '-' : ''}${mantissa}e${power}`);
  }
}

class StreamingQuintParseJsonParser {
  private readonly frames: JsonContainerFrame[] = [];
  private mode: 'normal' | 'string' | 'escape' | 'unicode' | 'number' | 'literal' = 'normal';
  private rootStarted = false;
  private rootComplete = false;
  private rootObject: ParseRootBuilder | undefined;
  private stringCapture: JsonStringCapture | undefined;
  private stringIsKey = false;
  private stringTarget: JsonValueTarget | undefined;
  private stringKeyFrame: JsonContainerFrame | undefined;
  private unicodeDigits = '';
  private numberCapture: JsonNumberCapture | undefined;
  private numberTarget: JsonValueTarget | undefined;
  private numberState: JsonNumberState = 'start';
  private literal = '';
  private literalIndex = 0;
  private literalTarget: JsonValueTarget | undefined;

  write(input: string): void {
    let index = 0;
    while (index < input.length) {
      const consumed = this.consumeCharacter(input.charAt(index));
      if (consumed) {
        index += 1;
      }
    }
  }

  finish(): void {
    if (this.mode === 'number') {
      this.finishNumber();
    }
    if (this.mode !== 'normal' || this.frames.length > 0 || !this.rootStarted || !this.rootComplete) {
      throw new Error('Invalid or incomplete JSON');
    }
  }

  failureMessage(): string | undefined {
    const errors = this.rootObject?.errors;
    if (!this.rootObject?.errorsSeen
      || !this.rootObject.errorsIsArray
      || errors === undefined
      || errors.invalid
      || errors.count === 0n) {
      return undefined;
    }
    return formatCollectedQuintParseDiagnostics(errors);
  }

  private consumeCharacter(character: string): boolean {
    if (this.mode === 'string') return this.consumeStringCharacter(character);
    if (this.mode === 'escape') return this.consumeEscapeCharacter(character);
    if (this.mode === 'unicode') return this.consumeUnicodeCharacter(character);
    if (this.mode === 'number') return this.consumeNumberCharacter(character);
    if (this.mode === 'literal') return this.consumeLiteralCharacter(character);
    return this.consumeJsonCharacter(character);
  }

  private consumeJsonCharacter(character: string): boolean {
    const frame = this.frames.at(-1);
    if (!frame) {
      if (this.rootComplete) {
        if (this.isJsonWhitespace(character)) return true;
        throw new Error('Unexpected data after JSON value');
      }
      if (this.isJsonWhitespace(character)) return true;
      this.beginValue(character);
      return true;
    }

    if (frame.kind === 'object') {
      if (frame.state === 'keyOrEnd' || frame.state === 'key') {
        if (this.isJsonWhitespace(character)) return true;
        if (frame.state === 'keyOrEnd' && character === '}') {
          this.closeContainer();
          return true;
        }
        if (character !== '"') throw new Error('Expected JSON object key');
        this.startStringKey(frame);
        return true;
      }
      if (frame.state === 'colon') {
        if (this.isJsonWhitespace(character)) return true;
        if (character !== ':') throw new Error('Expected colon after JSON object key');
        frame.state = 'value';
        return true;
      }
      if (frame.state === 'value') {
        if (this.isJsonWhitespace(character)) return true;
        this.beginValue(character);
        return true;
      }
      if (this.isJsonWhitespace(character)) return true;
      if (character === ',') {
        frame.state = 'key';
        return true;
      }
      if (character === '}') {
        this.closeContainer();
        return true;
      }
      throw new Error('Expected comma or closing brace');
    }

    if (frame.state === 'valueOrEnd' || frame.state === 'value') {
      if (this.isJsonWhitespace(character)) return true;
      if (frame.state === 'valueOrEnd' && character === ']') {
        this.closeContainer();
        return true;
      }
      this.beginValue(character);
      return true;
    }
    if (this.isJsonWhitespace(character)) return true;
    if (character === ',') {
      frame.state = 'value';
      return true;
    }
    if (character === ']') {
      this.closeContainer();
      return true;
    }
    throw new Error('Expected comma or closing bracket');
  }

  private beginValue(character: string): void {
    const target = this.takeValueTarget();
    if (character === '{') {
      this.openObject(target);
    } else if (character === '[') {
      this.openArray(target);
    } else if (character === '"') {
      this.startStringValue(target);
    } else if (character === '-' || (character >= '0' && character <= '9')) {
      this.numberCapture = new JsonNumberCapture();
      this.numberTarget = target;
      this.numberState = 'start';
      this.mode = 'number';
      this.consumeNumberCharacter(character);
    } else if (character === 't' || character === 'f' || character === 'n') {
      this.literal = character === 't' ? 'true' : character === 'f' ? 'false' : 'null';
      this.literalIndex = 1;
      this.literalTarget = target;
      this.mode = 'literal';
    } else {
      throw new Error('Invalid JSON value');
    }
  }

  private takeValueTarget(): JsonValueTarget {
    const frame = this.frames.at(-1);
    if (!frame) {
      if (this.rootStarted) throw new Error('Multiple top-level JSON values');
      this.rootStarted = true;
      return { kind: 'root' };
    }

    if (frame.kind === 'array') {
      frame.state = 'commaOrEnd';
      if (frame.role === 'errors') {
        return { kind: 'diagnosticElement', errors: frame.data as ParseErrorsCollector };
      }
      if (frame.role === 'locations') {
        return { kind: 'locationElement', locations: frame.data as ParseLocationsCollector };
      }
      return { kind: 'other' };
    }

    const key = frame.key;
    frame.key = undefined;
    frame.state = 'commaOrEnd';
    if (key === undefined) return { kind: 'other' };
    if (frame.role === 'root' && key === 'errors') {
      return { kind: 'rootErrors', root: frame.data as ParseRootBuilder };
    }
    if (frame.role === 'diagnostic') {
      const diagnostic = frame.data as ParseDiagnosticBuilder;
      if (key === 'explanation') return { kind: 'diagnosticExplanation', diagnostic };
      if (key === 'locs') return { kind: 'diagnosticLocations', diagnostic };
    }
    if (frame.role === 'location') {
      const location = frame.data as ParseLocationBuilder;
      if (key === 'source') return { kind: 'locationSource', location };
      if (key === 'start') return { kind: 'locationStart', location };
    }
    if (frame.role === 'position') {
      const position = frame.data as ParsePositionBuilder;
      if (key === 'line') return { kind: 'positionLine', position };
      if (key === 'col') return { kind: 'positionColumn', position };
    }
    return { kind: 'other' };
  }

  private openObject(target: JsonValueTarget): void {
    let role: JsonRole = 'other';
    let data: JsonContainerFrame['data'];
    if (target.kind === 'root') {
      const root: ParseRootBuilder = { errorsSeen: false, errorsIsArray: false };
      this.rootObject = root;
      role = 'root';
      data = root;
    } else if (target.kind === 'diagnosticElement') {
      const diagnostic: ParseDiagnosticBuilder = { errors: target.errors };
      role = 'diagnostic';
      data = diagnostic;
    } else if (target.kind === 'locationElement') {
      const location: ParseLocationBuilder = { locations: target.locations };
      role = 'location';
      data = location;
    } else if (target.kind === 'locationStart') {
      const position: ParsePositionBuilder = {};
      target.location.start = position;
      role = 'position';
      data = position;
    } else {
      this.rejectContainerTarget(target);
    }
    this.frames.push({ kind: 'object', role, data, state: 'keyOrEnd' });
  }

  private openArray(target: JsonValueTarget): void {
    let role: JsonRole = 'other';
    let data: JsonContainerFrame['data'];
    if (target.kind === 'rootErrors') {
      const errors: ParseErrorsCollector = {
        invalid: false,
        count: 0n,
        candidates: [],
        retainingCandidates: true,
      };
      target.root.errorsIsArray = true;
      target.root.errors = errors;
      role = 'errors';
      data = errors;
    } else if (target.kind === 'diagnosticLocations') {
      const locations: ParseLocationsCollector = {
        invalid: false,
        count: 0,
        text: new BoundedParseText(),
        positionEnds: [],
      };
      target.diagnostic.locations = locations;
      role = 'locations';
      data = locations;
    } else {
      this.rejectContainerTarget(target);
    }
    this.frames.push({ kind: 'array', role, data, state: 'valueOrEnd' });
  }

  private rejectContainerTarget(target: JsonValueTarget): void {
    if (target.kind === 'root') {
      this.rootObject = undefined;
      return;
    }
    if (target.kind === 'rootErrors') {
      target.root.errorsIsArray = false;
      target.root.errors = undefined;
      return;
    }
    if (target.kind === 'diagnosticElement') {
      target.errors.invalid = true;
      return;
    }
    if (target.kind === 'locationElement') {
      target.locations.invalid = true;
    }
  }

  private startStringKey(frame: JsonContainerFrame): void {
    this.stringCapture = new JsonStringCapture(32, true, false);
    this.stringIsKey = true;
    this.stringKeyFrame = frame;
    this.mode = 'string';
  }

  private startStringValue(target: JsonValueTarget): void {
    const capturesSource = target.kind === 'locationSource';
    const capturesText = target.kind === 'diagnosticExplanation' || capturesSource;
    this.stringCapture = new JsonStringCapture(
      MAX_RETAINED_PARSE_TEXT,
      capturesText,
      capturesSource,
    );
    this.stringIsKey = false;
    this.stringTarget = target;
    this.mode = 'string';
  }

  private consumeStringCharacter(character: string): boolean {
    if (character === '"') {
      this.finishString();
      return true;
    }
    if (character === '\\') {
      this.mode = 'escape';
      return true;
    }
    if (character.charCodeAt(0) < 0x20) throw new Error('Unescaped control character in JSON string');
    this.stringCapture?.append(character);
    return true;
  }

  private consumeEscapeCharacter(character: string): boolean {
    if (character === 'u') {
      this.unicodeDigits = '';
      this.mode = 'unicode';
      return true;
    }
    const decoded = JSON_STRING_ESCAPES[character];
    if (decoded === undefined) throw new Error('Invalid JSON escape');
    this.stringCapture?.append(decoded);
    this.mode = 'string';
    return true;
  }

  private consumeUnicodeCharacter(character: string): boolean {
    if (!/[0-9a-f]/iu.test(character)) throw new Error('Invalid JSON unicode escape');
    this.unicodeDigits += character;
    if (this.unicodeDigits.length === 4) {
      this.stringCapture?.append(String.fromCharCode(Number.parseInt(this.unicodeDigits, 16)));
      this.mode = 'string';
    }
    return true;
  }

  private finishString(): void {
    const value = this.stringCapture?.finish();
    this.stringCapture = undefined;
    this.mode = 'normal';
    if (this.stringIsKey) {
      const frame = this.stringKeyFrame;
      if (!frame || !value) throw new Error('JSON key has no object context');
      const key = value.prefixComplete ? value.prefix : undefined;
      frame.key = key;
      frame.state = 'colon';
      if (key === 'errors' && frame.role === 'root') {
        const root = frame.data as ParseRootBuilder;
        root.errorsSeen = true;
        root.errorsIsArray = false;
        root.errors = undefined;
      } else if (frame.role === 'diagnostic') {
        const diagnostic = frame.data as ParseDiagnosticBuilder;
        if (key === 'explanation') diagnostic.explanation = undefined;
        if (key === 'locs') diagnostic.locations = undefined;
      } else if (frame.role === 'location') {
        const location = frame.data as ParseLocationBuilder;
        if (key === 'source') location.source = undefined;
        if (key === 'start') location.start = undefined;
      } else if (frame.role === 'position') {
        const position = frame.data as ParsePositionBuilder;
        if (key === 'line') position.line = undefined;
        if (key === 'col') position.col = undefined;
      }
      this.stringKeyFrame = undefined;
      this.stringIsKey = false;
      return;
    }
    const target = this.stringTarget;
    this.stringTarget = undefined;
    if (!target || !value) throw new Error('JSON string has no value context');
    this.finishPrimitive(target, { kind: 'string', value });
    this.completeTopLevelValueIfNeeded();
  }

  private consumeNumberCharacter(character: string): boolean {
    const previousState = this.numberState;
    let nextState: JsonNumberState | undefined;
    if (previousState === 'start') {
      if (character === '-') nextState = 'afterMinus';
      else if (character === '0') nextState = 'zero';
      else if (character >= '1' && character <= '9') nextState = 'integer';
    } else if (previousState === 'afterMinus') {
      if (character === '0') nextState = 'zero';
      else if (character >= '1' && character <= '9') nextState = 'integer';
    } else if (previousState === 'zero') {
      if (character === '.') nextState = 'fractionStart';
      else if (character === 'e' || character === 'E') nextState = 'exponentStart';
    } else if (previousState === 'integer') {
      if (character >= '0' && character <= '9') nextState = 'integer';
      else if (character === '.') nextState = 'fractionStart';
      else if (character === 'e' || character === 'E') nextState = 'exponentStart';
    } else if (previousState === 'fractionStart') {
      if (character >= '0' && character <= '9') nextState = 'fraction';
    } else if (previousState === 'fraction') {
      if (character >= '0' && character <= '9') nextState = 'fraction';
      else if (character === 'e' || character === 'E') nextState = 'exponentStart';
    } else if (previousState === 'exponentStart') {
      if (character === '+' || character === '-') nextState = 'exponentSign';
      else if (character >= '0' && character <= '9') nextState = 'exponentDigits';
    } else if (previousState === 'exponentSign') {
      if (character >= '0' && character <= '9') nextState = 'exponentDigits';
    } else if (previousState === 'exponentDigits' && character >= '0' && character <= '9') {
      nextState = 'exponentDigits';
    }

    if (nextState !== undefined) {
      this.numberCapture?.append(character, previousState);
      this.numberState = nextState;
      return true;
    }
    if (previousState === 'zero' || previousState === 'integer' || previousState === 'fraction' || previousState === 'exponentDigits') {
      this.finishNumber();
      return false;
    }
    throw new Error('Invalid JSON number');
  }

  private finishNumber(): void {
    if (this.numberState !== 'zero'
      && this.numberState !== 'integer'
      && this.numberState !== 'fraction'
      && this.numberState !== 'exponentDigits') {
      throw new Error('Incomplete JSON number');
    }
    const target = this.numberTarget;
    const value = this.numberCapture?.toNumber();
    this.numberCapture = undefined;
    this.numberTarget = undefined;
    this.mode = 'normal';
    if (target === undefined || value === undefined) throw new Error('JSON number has no value context');
    this.finishPrimitive(target, { kind: 'number', value });
    this.completeTopLevelValueIfNeeded();
  }

  private consumeLiteralCharacter(character: string): boolean {
    if (character !== this.literal[this.literalIndex]) throw new Error('Invalid JSON literal');
    this.literalIndex += 1;
    if (this.literalIndex === this.literal.length) {
      const target = this.literalTarget;
      const literal = this.literal;
      this.literal = '';
      this.literalTarget = undefined;
      this.mode = 'normal';
      if (!target) throw new Error('JSON literal has no value context');
      this.finishPrimitive(target, literal === 'null'
        ? { kind: 'null' }
        : { kind: 'boolean', value: literal === 'true' });
      this.completeTopLevelValueIfNeeded();
    }
    return true;
  }

  private finishPrimitive(
    target: JsonValueTarget,
    value: { readonly kind: 'string'; readonly value: StreamedJsonString }
      | { readonly kind: 'number'; readonly value: number }
      | { readonly kind: 'boolean'; readonly value: boolean }
      | { readonly kind: 'null' },
  ): void {
    if (target.kind === 'diagnosticElement') {
      target.errors.invalid = true;
    } else if (target.kind === 'diagnosticExplanation' && value.kind === 'string') {
      target.diagnostic.explanation = value.value;
    } else if (target.kind === 'locationElement') {
      target.locations.invalid = true;
    } else if (target.kind === 'locationSource' && value.kind === 'string') {
      target.location.source = value.value;
    } else if (target.kind === 'positionLine') {
      target.position.line = value.kind === 'number' && Number.isInteger(value.value) && value.value >= 0
        ? value.value
        : undefined;
    } else if (target.kind === 'positionColumn') {
      target.position.col = value.kind === 'number' && Number.isInteger(value.value) && value.value >= 0
        ? value.value
        : undefined;
    } else if (target.kind === 'root') {
      this.rootObject = undefined;
    } else if (target.kind === 'rootErrors') {
      target.root.errorsIsArray = false;
      target.root.errors = undefined;
    }
  }

  private closeContainer(): void {
    const frame = this.frames.pop();
    if (!frame) throw new Error('Unexpected JSON closing delimiter');
    if (frame.role === 'location') {
      this.finishLocation(frame.data as ParseLocationBuilder);
    } else if (frame.role === 'diagnostic') {
      this.finishDiagnostic(frame.data as ParseDiagnosticBuilder);
    }
    if (this.frames.length === 0) {
      this.rootComplete = true;
    }
  }

  private finishLocation(location: ParseLocationBuilder): void {
    const source = location.source;
    const position = location.start;
    if (source === undefined || position?.line === undefined || position.col === undefined) {
      location.locations.invalid = true;
      return;
    }
    const positionText = new BoundedParseText();
    const rendered = `${source.basename}:${position.line + 1}:${position.col + 1}`;
    positionText.append(
      rendered,
      source.basenameLength + `:${position.line + 1}:${position.col + 1}`.length,
      source.basenameComplete,
    );
    const locations = location.locations;
    if (locations.count === 0) locations.firstPosition = positionText;
    if (locations.count > 0) locations.text.append(', ');
    locations.text.append(positionText.text, positionText.length, positionText.complete);
    if (locations.text.complete && locations.text.text.length === locations.text.length) {
      locations.positionEnds.push(locations.text.text.length);
    }
    locations.count += 1;
  }

  private finishDiagnostic(diagnostic: ParseDiagnosticBuilder): void {
    const locations = diagnostic.locations;
    const explanation = diagnostic.explanation;
    if (locations === undefined
      || locations.invalid
      || locations.count === 0
      || explanation === undefined) {
      diagnostic.errors.invalid = true;
      return;
    }

    const text = new BoundedParseText();
    text.append(locations.text.text, locations.text.length, locations.text.complete);
    text.append(': ');
    text.append(explanation.prefix, explanation.length, explanation.prefixComplete);
    const errors = diagnostic.errors;
    errors.count += 1n;
    if (!errors.retainingCandidates) return;

    const prior = errors.candidates.at(-1);
    const candidate: ParseDiagnosticCandidate = {
      text: text.text,
      complete: text.complete,
      prefixLength: (prior?.prefixLength ?? 0) + (prior ? 1 : 0) + text.text.length,
      ...(errors.count === 1n && !text.complete && locations.firstPosition !== undefined
        ? {
            truncatedLocations: {
              positions: locations.text.text,
              positionEnds: [...locations.positionEnds],
              firstPosition: locations.firstPosition.text,
              explanation: explanation.prefix,
            },
          }
        : {}),
    };
    errors.candidates.push(candidate);
    if (!candidate.complete || candidate.prefixLength > MAX_FAILURE_MESSAGE) {
      errors.retainingCandidates = false;
    }
  }

  private completeTopLevelValueIfNeeded(): void {
    if (this.frames.length === 0) this.rootComplete = true;
  }

  private isJsonWhitespace(character: string): boolean {
    return character === ' ' || character === '\t' || character === '\n' || character === '\r';
  }
}

function formatCollectedQuintParseDiagnostics(errors: ParseErrorsCollector): string {
  const totalCount = errors.count;
  const candidates = errors.candidates;
  const lastCandidate = candidates.at(-1);
  if (totalCount === BigInt(candidates.length)
    && lastCandidate !== undefined
    && lastCandidate.complete
    && lastCandidate.prefixLength <= MAX_FAILURE_MESSAGE) {
    return candidates.map(({ text }) => text).join('\n');
  }

  for (let includedCount = candidates.length; includedCount > 0; includedCount -= 1) {
    const included = candidates[includedCount - 1]!;
    if (!included.complete) continue;
    const omittedCount = totalCount - BigInt(includedCount);
    const omissionNote = `他 ${omittedCount} 件の診断を省略`;
    if (omittedCount === 0n && included.prefixLength <= MAX_FAILURE_MESSAGE) {
      return candidates.slice(0, includedCount).map(({ text }) => text).join('\n');
    }
    if (omittedCount > 0n && included.prefixLength + 1 + omissionNote.length <= MAX_FAILURE_MESSAGE) {
      return `${candidates.slice(0, includedCount).map(({ text }) => text).join('\n')}\n${omissionNote}`;
    }
  }

  const first = candidates[0];
  if (!first) throw new Error('No retained Quint parse diagnostic');
  const omissionNote = `他 ${totalCount - 1n} 件の診断を省略`;
  if (first.truncatedLocations !== undefined) {
    const contentBudget = MAX_FAILURE_MESSAGE
      - OUTPUT_TRUNCATED_SUFFIX.length
      - 1
      - omissionNote.length;
    const { positions, positionEnds, firstPosition, explanation } = first.truncatedLocations;
    const firstPositionEnd = positionEnds[0];
    const hasCompleteFirstPosition = firstPositionEnd !== undefined;
    const minimumExplanationLength = explanation.length > 0 ? 1 : 0;
    const maxFirstPositionLength = Math.max(0, contentBudget - 2 - minimumExplanationLength);
    const firstPositionBudget = hasCompleteFirstPosition
      && firstPosition.length <= maxFirstPositionLength
      ? firstPosition.length
      : maxFirstPositionLength;
    const retainedFirstPosition = firstPosition.slice(0, firstPositionBudget);
    const explanationBudget = Math.max(0, contentBudget - retainedFirstPosition.length - 2);
    const retainedExplanation = explanation.slice(0, explanationBudget);
    const positionsBudget = contentBudget - 2 - retainedExplanation.length;
    let lastPositionEnd: number | undefined;
    for (const end of positionEnds) {
      if (end > positionsBudget) break;
      lastPositionEnd = end;
    }
    const retainedPositions = lastPositionEnd === undefined
      ? retainedFirstPosition
      : positions.slice(0, lastPositionEnd);
    return `${retainedPositions}: ${retainedExplanation}${OUTPUT_TRUNCATED_SUFFIX}\n${omissionNote}`;
  }
  const partialDiagnosticLength = MAX_FAILURE_MESSAGE
    - OUTPUT_TRUNCATED_SUFFIX.length
    - 1
    - omissionNote.length;
  return `${first.text.slice(0, partialDiagnosticLength)}${OUTPUT_TRUNCATED_SUFFIX}\n${omissionNote}`;
}

async function quintParseFailureMessage(result: ProcessResult, parseJsonPath: string): Promise<string> {
  let file: Awaited<ReturnType<typeof open>> | undefined;
  try {
    file = await open(parseJsonPath, 'r');
    const parser = new StreamingQuintParseJsonParser();
    const decoder = new StringDecoder('utf8');
    const buffer = Buffer.alloc(QUINT_PARSE_READ_BUFFER_SIZE);
    while (true) {
      const { bytesRead } = await file.read(buffer, 0, buffer.length, null);
      if (bytesRead === 0) break;
      parser.write(decoder.write(buffer.subarray(0, bytesRead)));
    }
    parser.write(decoder.end());
    parser.finish();
    return parser.failureMessage() ?? processFailureMessage(result);
  } catch {
    return processFailureMessage(result);
  } finally {
    if (file !== undefined) {
      await file.close().catch(() => undefined);
    }
  }
}

function tlcFailureMessage(result: ProcessResult): string {
  // Preserve unrecognized failures instead of replacing their details with a generic summary.
  const output = extractTlcDiagnostics(result.stdout) ?? rawProcessOutput(result);
  const notices: string[] = [];
  if (result.outcome === 'timeout') {
    notices.push(TLC_TIMEOUT_GUIDANCE);
  }
  if (result.stdoutTruncated || result.stderrTruncated) {
    notices.push(TLC_OUTPUT_TRUNCATED_MESSAGE);
  }
  return formatProcessFailureMessage(result, output, notices.join('\n'));
}

function passedStage(): FormalSpecStageResult {
  return { status: 'passed' };
}

function skippedStage(message: string): FormalSpecStageResult {
  return { status: 'skipped', message };
}

function failedStage(result: ProcessResult): FormalSpecStageResult {
  return { status: 'failed', message: processFailureMessage(result) };
}

function errorStage(message: string): FormalSpecStageResult {
  return { status: 'error', message };
}

function isSuccessfulProcess(result: ProcessResult): boolean {
  return result.outcome === 'exit' && result.status === 0;
}

function specificationProcessStage(result: ProcessResult): FormalSpecStageResult {
  return isSuccessfulProcess(result)
    ? passedStage()
    : errorStage(processFailureMessage(result));
}

function verificationProcessStage(
  result: ProcessResult,
  backend: QuintVerificationBackend,
): FormalSpecStageResult {
  if (isSuccessfulProcess(result)) {
    return passedStage();
  }
  const message = backend === 'tlc' ? tlcFailureMessage(result) : processFailureMessage(result);
  return result.outcome === 'exit' && result.status !== null
    ? { status: 'failed', message }
    : errorStage(message);
}

interface QuintRunOutputParser {
  consume(chunk: string): void;
  finish(): readonly string[];
}

interface QuintRunOutputParts {
  readonly trace: string;
  readonly auxiliaryOutput: string;
}

function createQuintRunOutputParser(invariantNames: readonly string[]): QuintRunOutputParser {
  const expectedNames = new Set(invariantNames);
  let maximumInvariantNameLength = 0;
  for (const name of invariantNames) {
    maximumInvariantNameLength = Math.max(maximumInvariantNameLength, name.length);
  }

  const headerLineLimit = QUINT_VIOLATION_HEADER.length + 2;
  const violationLineLimit = QUINT_VIOLATION_MARKER.length + 1 + maximumInvariantNameLength;
  const resultLineLimit = Math.max(headerLineLimit, violationLineLimit, QUINT_VIOLATION_TERMINAL.length);
  const violatedNames: string[] = [];
  const seenNames = new Set<string>();
  let violationHeaderFound = false;
  let collectingViolationNames = false;
  let resultSectionEnded = false;
  let skippingHeaderLine = false;
  let line = '';
  let pendingWhitespace = false;
  let lineTooLong = false;
  let ansiState: 'text' | 'escape' | 'csi' = 'text';
  let previousCharacterWasCarriageReturn = false;

  const resetLine = (): void => {
    line = '';
    pendingWhitespace = false;
    lineTooLong = false;
  };

  const finishLine = (): void => {
    if (skippingHeaderLine) {
      skippingHeaderLine = false;
      resetLine();
      return;
    }

    if (!lineTooLong) {
      if (!violationHeaderFound && QUINT_VIOLATION_HEADER_PATTERN.test(line)) {
        violationHeaderFound = true;
        collectingViolationNames = true;
      } else if (collectingViolationNames) {
        if (line === QUINT_VIOLATION_TERMINAL) {
          collectingViolationNames = false;
          resultSectionEnded = true;
        } else {
          const name = QUINT_VIOLATION_NAME_PATTERN.exec(line)?.[1];
          if (name !== undefined && expectedNames.has(name) && !seenNames.has(name)) {
            seenNames.add(name);
            violatedNames.push(name);
          }
        }
      }
    }

    resetLine();
  };

  const consumeVisibleCharacter = (character: string): void => {
    if (resultSectionEnded) return;
    if (previousCharacterWasCarriageReturn) {
      previousCharacterWasCarriageReturn = false;
      if (character === '\n') {
        return;
      }
    }

    if (character === '\r') {
      finishLine();
      previousCharacterWasCarriageReturn = true;
      return;
    }
    if (character === '\n') {
      finishLine();
      return;
    }
    if (skippingHeaderLine || lineTooLong) {
      return;
    }
    if (/\s/u.test(character)) {
      if (line.length > 0) {
        pendingWhitespace = true;
      }
      return;
    }

    if (pendingWhitespace) {
      line += ' ';
      pendingWhitespace = false;
    }
    line += character;

    if (!violationHeaderFound && QUINT_VIOLATION_HEADER_PREFIX_PATTERN.test(line)) {
      violationHeaderFound = true;
      collectingViolationNames = true;
      skippingHeaderLine = true;
      resetLine();
      return;
    }

    const lineLimit = violationHeaderFound ? resultLineLimit : headerLineLimit;
    if (line.length > lineLimit) {
      line = '';
      pendingWhitespace = false;
      lineTooLong = true;
    }
  };

  const consume = (chunk: string): void => {
    for (const character of chunk) {
      if (ansiState === 'escape') {
        ansiState = character === '[' ? 'csi' : 'text';
        if (character !== '[') {
          consumeVisibleCharacter(character);
        }
      } else if (ansiState === 'csi') {
        const code = character.charCodeAt(0);
        if (code >= 0x40 && code <= 0x7e) {
          ansiState = 'text';
        }
      } else if (character === '\u001b') {
        ansiState = 'escape';
      } else {
        consumeVisibleCharacter(character);
      }
    }
  };

  const finish = (): readonly string[] => {
    if (!previousCharacterWasCarriageReturn) {
      finishLine();
    }
    return [...violatedNames];
  };

  return { consume, finish };
}

function splitQuintRunOutput(stdout: string): QuintRunOutputParts {
  const lineBreakPattern = /\r\n?|\n/gu;
  let lineStart = 0;
  let match: RegExpExecArray | null;

  while ((match = lineBreakPattern.exec(stdout)) !== null) {
    const line = stdout.slice(lineStart, match.index);
    if (QUINT_VIOLATION_HEADER_PATTERN.test(line.replace(ANSI_ESCAPE_PATTERN, '').trim())) {
      return {
        trace: stdout.slice(0, lineStart).trim(),
        auxiliaryOutput: stdout.slice(lineStart).trim(),
      };
    }
    lineStart = match.index + match[0].length;
  }

  const finalLine = stdout.slice(lineStart);
  if (QUINT_VIOLATION_HEADER_PATTERN.test(finalLine.replace(ANSI_ESCAPE_PATTERN, '').trim())) {
    return {
      trace: stdout.slice(0, lineStart).trim(),
      auxiliaryOutput: finalLine.trim(),
    };
  }

  return { trace: stdout.trim(), auxiliaryOutput: '' };
}

function formatTruncatedQuintRunFailureMessage(
  invariantName: string,
  details: readonly string[],
  trace: string,
): string {
  const namePrefix = invariantName.slice(0, Math.min(invariantName.length, 'inv'.length));
  const minimumDisplayedName = `${QUINT_VIOLATION_MARKER} ${namePrefix}${QUINT_INVARIANT_NAME_TRUNCATED_SUFFIX}`;
  const minimumPrefix = [minimumDisplayedName, ...details]
    .filter((part) => part.length > 0)
    .join('\n');
  const separator = trace.length > 0 ? '\n' : '';
  const traceBudget = MAX_FAILURE_MESSAGE - minimumPrefix.length - separator.length;

  if (trace.length > traceBudget) {
    const retainedTraceLength = Math.max(0, traceBudget - OUTPUT_TRUNCATED_SUFFIX.length);
    return `${minimumPrefix}${separator}${trace.slice(0, retainedTraceLength)}${OUTPUT_TRUNCATED_SUFFIX}`;
  }

  const messageWithoutName = [
    `${QUINT_VIOLATION_MARKER} ${QUINT_INVARIANT_NAME_TRUNCATED_SUFFIX}`,
    ...details,
    trace,
  ].filter((part) => part.length > 0).join('\n');
  const retainedNameLength = MAX_FAILURE_MESSAGE - messageWithoutName.length;
  const displayedName = `${QUINT_VIOLATION_MARKER} ${invariantName.slice(0, retainedNameLength)}${QUINT_INVARIANT_NAME_TRUNCATED_SUFFIX}`;
  return [displayedName, ...details, trace]
    .filter((part) => part.length > 0)
    .join('\n');
}

function formatQuintRunFailureMessage(
  result: ProcessResult,
  violatedNames: readonly string[],
): string {
  const output = splitQuintRunOutput(result.stdout);
  const details = [result.error, result.stderr.trim()]
    .filter((detail): detail is string => detail !== undefined && detail.length > 0);
  const names = violatedNames.map((name) => `${QUINT_VIOLATION_MARKER} ${name}`);
  const makeMessage = (includedNames: readonly string[], includeAuxiliaryOutput = false): string => [
    ...includedNames,
    ...details,
    output.trace,
    ...(includeAuxiliaryOutput ? [output.auxiliaryOutput] : []),
  ].filter((part) => part.length > 0).join('\n');

  let message = makeMessage(names.slice(0, 1));
  if (message.length <= MAX_FAILURE_MESSAGE) {
    const includedNames = names.slice(0, 1);
    for (const name of names.slice(1)) {
      const candidate = makeMessage([...includedNames, name]);
      if (candidate.length > MAX_FAILURE_MESSAGE) break;
      includedNames.push(name);
    }

    message = makeMessage(includedNames, true);
    return message.length <= MAX_FAILURE_MESSAGE
      ? message
      : makeMessage(includedNames);
  }

  const nameAndDetails = [names[0]!, ...details]
    .filter((part) => part.length > 0)
    .join('\n');
  const traceSeparator = output.trace.length > 0 ? '\n' : '';
  const retainedTraceBudget = MAX_FAILURE_MESSAGE
    - nameAndDetails.length
    - traceSeparator.length
    - OUTPUT_TRUNCATED_SUFFIX.length;
  if (retainedTraceBudget > 0) {
    return `${nameAndDetails}${traceSeparator}${output.trace.slice(0, retainedTraceBudget)}${OUTPUT_TRUNCATED_SUFFIX}`;
  }

  const invariantName = violatedNames[0]!;
  if (invariantName.length === MAX_FAILURE_MESSAGE) {
    return invariantName;
  }

  const separator = output.trace.length > 0 ? '\n' : '';
  const traceBudget = MAX_FAILURE_MESSAGE - invariantName.length - separator.length;
  if (traceBudget < 0) {
    return formatTruncatedQuintRunFailureMessage(invariantName, details, output.trace);
  }

  return `${invariantName}${separator}${output.trace.slice(0, traceBudget)}`;
}

function quintRunProcessStage(
  result: ProcessResult,
  invariantNames: readonly string[],
  parsedViolationNames: readonly string[],
): FormalSpecStageResult {
  const stage = verificationProcessStage(result, 'typescript');
  if (stage.status !== 'failed' || result.stderrTruncated || result.stderr.trim() !== 'error: Invariant violated') {
    return stage;
  }

  const violatedNames = [...parsedViolationNames];
  if (violatedNames.length === 0 && invariantNames.length === 1) {
    violatedNames.push(invariantNames[0]!);
  }
  if (violatedNames.length === 0) {
    return stage;
  }

  return {
    ...stage,
    message: formatQuintRunFailureMessage(result, violatedNames),
  };
}

function selectPrimaryStage(stages: readonly FormalSpecStageResult[]): FormalSpecStageResult {
  return stages.find((stage) => stage.status === 'error')
    ?? stages.find((stage) => stage.status === 'failed')
    ?? stages.find((stage) => stage.status === 'passed')
    ?? stages.find((stage) => stage.status === 'skipped')
    ?? skippedStage('No verification stage was executed.');
}

function aggregateStageResult(
  stages: readonly FormalSpecStageResult[],
  emptyMessage: string,
): FormalSpecStageResult {
  return stages.length > 0 ? selectPrimaryStage(stages) : skippedStage(emptyMessage);
}

/** Remove abandoned verify run workspaces older than the stale threshold. */
function cleanupAbandonedVerifyRuns(cwd: string): void {
  const runsDirectory = join(cwd, '.takt', 'runs');
  let entries;
  try {
    entries = readdirSync(runsDirectory, { withFileTypes: true });
  } catch {
    return;
  }
  const staleBefore = Date.now() - STALE_VERIFY_RUN_MAX_AGE_MS;
  for (const entry of entries) {
    if (!entry.isDirectory() || !entry.name.startsWith('verify-')) continue;
    const directory = join(runsDirectory, entry.name);
    try {
      if (statSync(directory).mtimeMs < staleBefore) {
        removeVerifyRunDirectory(directory);
      }
    } catch {
      // A workspace removed concurrently is not an error.
    }
  }
}

function removeVerifyRunDirectory(directory: string): void {
  try {
    rmSync(directory, { recursive: true, force: true });
  } catch {
    // Cleanup is best effort and must not replace the verification result.
  }
}

function createRunDirectory(cwd: string): string {
  const runsDirectory = join(cwd, '.takt', 'runs');
  mkdirSync(runsDirectory, { recursive: true });
  const runDirectory = mkdtempSync(join(runsDirectory, 'verify-'));
  try {
    mkdirSync(join(runDirectory, 'specs'), { mode: 0o700 });
  } catch (error) {
    removeVerifyRunDirectory(runDirectory);
    throw error;
  }
  return runDirectory;
}

function writeSpecification(directory: string, name: string, blocks: readonly string[]): string {
  const path = join(directory, 'specs', name);
  writeFileSync(path, `${blocks.join('\n\n')}\n`, { encoding: 'utf8', mode: 0o600 });
  return path;
}

function resolveQuintCli(): string {
  return require.resolve('@informalsystems/quint/dist/src/cli.js') as string;
}

function skippedQuintResult(message: string): FormalSpecQuintResult {
  return { status: 'skipped', message };
}

function skippedAlloyResult(message: string): FormalSpecAlloyResult {
  return { status: 'skipped', message };
}

function resultForNoBlocks(message: string): FormalSpecVerificationResult {
  return {
    verdict: 'error',
    verificationStarted: false,
    message,
    quint: skippedQuintResult(message),
    alloy: skippedAlloyResult(message),
  };
}

function resultForUnexpectedError(
  error: unknown,
  verificationStarted: boolean,
): FormalSpecVerificationResult {
  const message = error instanceof Error ? error.message : String(error);
  return {
    verdict: 'error',
    verificationStarted,
    message,
    quint: errorStage(message),
    alloy: skippedAlloyResult('Verification stopped before Alloy could run.'),
  };
}

function parseAlloyCommands(output: string): AlloyParsedCommand[] {
  const commands: AlloyParsedCommand[] = [];
  for (const line of output.split(/\r\n?|\n/u)) {
    const match = /^\s*(\d+)\s*\.\s+(Check|Run)\s+(.+?)\s*$/iu.exec(line);
    if (!match) {
      continue;
    }
    const number = Number.parseInt(match[1] ?? '', 10);
    const type = (match[2] ?? '').toLowerCase();
    const label = (match[3] ?? '').replace(/\s+for\s+.+$/iu, '').trim();
    if (Number.isInteger(number) && label) {
      commands.push({ number, type, label });
    }
  }
  return commands;
}

function isUsableFile(path: string): boolean {
  try {
    return existsSync(path) && statSync(path).isFile() && statSync(path).size > 0;
  } catch {
    return false;
  }
}

function assertTrustedAlloyJar(bytes: Buffer, source: string): void {
  const digest = createHash('sha256').update(bytes).digest('hex');
  if (digest !== ALLOY_JAR_SHA256) {
    throw new Error(`Alloy jar SHA-256 mismatch for ${source}`);
  }
}

async function ensureAlloyJar(
  cwd: string,
  timeoutMs: number,
  abortSignal?: AbortSignal,
): Promise<string> {
  const configuredPath = process.env.TAKT_ALLOY_JAR;
  if (configuredPath) {
    const resolvedConfiguredPath = resolve(cwd, configuredPath);
    if (!isUsableFile(resolvedConfiguredPath)) {
      throw new Error(`Configured Alloy jar is not a readable file: ${resolvedConfiguredPath}`);
    }
    return resolvedConfiguredPath;
  }

  const cacheDirectory = join(cwd, '.takt', 'cache', 'alloy', ALLOY_VERSION);
  const cachedPath = join(cacheDirectory, 'alloy.jar');
  if (isUsableFile(cachedPath)) {
    assertTrustedAlloyJar(readFileSync(cachedPath), cachedPath);
    return cachedPath;
  }

  mkdirSync(cacheDirectory, { recursive: true, mode: 0o700 });
  const temporaryPath = join(cacheDirectory, `.alloy-${randomUUID()}.tmp`);
  try {
    const timeoutSignal = AbortSignal.timeout(timeoutMs);
    const signal = abortSignal === undefined
      ? timeoutSignal
      : AbortSignal.any([abortSignal, timeoutSignal]);
    const response = await fetch(ALLOY_JAR_URL, { signal });
    if (!response.ok) {
      throw new Error(`Alloy jar download failed with HTTP status ${response.status}`);
    }
    const bytes = Buffer.from(await response.arrayBuffer());
    if (bytes.length < 2 || bytes[0] !== 0x50 || bytes[1] !== 0x4b) {
      throw new Error('Alloy jar download did not return a valid archive');
    }
    assertTrustedAlloyJar(bytes, ALLOY_JAR_URL);
    writeFileSync(temporaryPath, bytes, { mode: 0o600 });
    renameSync(temporaryPath, cachedPath);
    return cachedPath;
  } finally {
    rmSync(temporaryPath, { force: true });
  }
}

async function javaVersion(
  cwd: string,
  abortSignal?: AbortSignal,
): Promise<number | undefined> {
  const result = await runProcess('java', ['-version'], cwd, 10_000, abortSignal);
  if (!isSuccessfulProcess(result)) {
    return undefined;
  }
  return detectJavaMajorVersion(`${result.stdout}\n${result.stderr}`);
}

async function runQuintCommand(
  quintCli: string,
  args: readonly string[],
  cwd: string,
  timeoutMs: number,
  abortSignal?: AbortSignal,
  onStdoutChunk?: (chunk: string) => void,
): Promise<ProcessResult> {
  return runProcess(
    process.execPath,
    [quintCli, ...args],
    cwd,
    timeoutMs,
    abortSignal,
    onStdoutChunk,
  );
}

async function runAlloyCommand(
  jarPath: string,
  args: readonly string[],
  cwd: string,
  timeoutMs: number,
  abortSignal?: AbortSignal,
): Promise<ProcessResult> {
  return runProcess(
    'java',
    ['-jar', jarPath, ...args],
    cwd,
    timeoutMs,
    abortSignal,
  );
}

interface QuintStageSet {
  readonly parse?: FormalSpecStageResult;
  readonly typecheck?: FormalSpecStageResult;
  readonly run?: FormalSpecStageResult;
  readonly verify?: FormalSpecStageResult;
}

function quintResultFromStages(
  stageSet: QuintStageSet,
  targets: QuintVerificationTargets,
): FormalSpecQuintResult {
  const stages = [stageSet.parse, stageSet.typecheck, stageSet.run, stageSet.verify]
    .filter((stage): stage is FormalSpecStageResult => stage !== undefined);
  const primary = aggregateStageResult(stages, 'No Quint verification stage was executed.');
  return {
    status: primary.status,
    ...(primary.message ? { message: primary.message } : {}),
    ...(stageSet.parse ? { parse: stageSet.parse } : {}),
    ...(stageSet.typecheck ? { typecheck: stageSet.typecheck } : {}),
    ...(stageSet.run ? { run: stageSet.run } : {}),
    ...(stageSet.verify ? { verify: stageSet.verify } : {}),
    invariants: targets.invariants.map(({ name }) => name),
    temporal: targets.temporal.map(({ name }) => name),
  };
}

/**
 * Extract and deterministically verify one newly generated provider response.
 * The conversation layer supplies only the response and resolved verifier options.
 */
export async function runFormalSpecVerification(
  response: string,
  cwd: string,
  options: FormalSpecVerificationOptions,
): Promise<FormalSpecVerificationResult> {
  const { abortSignal, modelCheckTimeoutSeconds } = options;
  abortSignal?.throwIfAborted();
  cleanupAbandonedVerifyRuns(cwd);
  let blocks: FormalSpecBlocks;
  try {
    blocks = extractFormalSpecBlocks(response);
  } catch (error) {
    return resultForUnexpectedError(error, false);
  }

  if (blocks.quint.length === 0 && blocks.alloy.length === 0) {
    return resultForNoBlocks('No formal specification blocks found.');
  }

  const modelCheckTimeoutMs = modelCheckTimeoutSeconds * 1000;

  let runDirectory: string | undefined;
  let verificationStarted = false;
  try {
    verificationStarted = true;
    runDirectory = createRunDirectory(cwd);
    const specsDirectory = join(runDirectory, 'specs');
    const quintPath = blocks.quint.length > 0
      ? writeSpecification(runDirectory, 'spec.qnt', blocks.quint)
      : undefined;
    const alloyPath = blocks.alloy.length > 0
      ? writeSpecification(runDirectory, 'spec.als', blocks.alloy)
      : undefined;

    const stages: FormalSpecStageResult[] = [];
    let quint: FormalSpecQuintResult;
    let targets: QuintVerificationTargets = { invariants: [], temporal: [] };
    let mainModule: string | undefined;
    let targetScopeError: string | undefined;
    let quintStageSet: QuintStageSet = {};
    if (!quintPath) {
      quint = skippedQuintResult('No Quint specification block was present.');
      stages.push(quint);
    } else {
      const quintCli = resolveQuintCli();
      const parseJsonPath = join(specsDirectory, 'parse.json');
      const parseProcessResult = await runQuintCommand(
        quintCli,
        ['parse', quintPath, '--out', parseJsonPath],
        runDirectory,
        QUINT_TIMEOUT_MS,
        abortSignal,
      );
      let parse = specificationProcessStage(parseProcessResult);
      if (parseProcessResult.outcome === 'exit'
        && parseProcessResult.status !== null
        && parseProcessResult.status !== 0) {
        parse = errorStage(await quintParseFailureMessage(parseProcessResult, parseJsonPath));
      }

      let parseResult: unknown;
      if (parse.status === 'passed') {
        try {
          parseResult = JSON.parse(readFileSync(parseJsonPath, 'utf8')) as unknown;
        } catch (error) {
          const message = `Quint parse output could not be read: ${error instanceof Error ? error.message : String(error)}`;
          parse = errorStage(message);
        }
      }

      let typecheck: FormalSpecStageResult = skippedStage('Quint typechecking was skipped because parsing did not pass.');
      let run: FormalSpecStageResult = skippedStage('Quint simulation was skipped because typechecking did not pass.');
      if (parse.status === 'passed') {
        targets = selectQuintVerificationTargets(parseResult);
        mainModule = selectQuintMainModule(parseResult);
        targetScopeError = mainModule === undefined
          ? undefined
          : quintTargetScopeError(targets, mainModule);
        typecheck = specificationProcessStage(
          await runQuintCommand(
            quintCli,
            ['typecheck', quintPath],
            runDirectory,
            QUINT_TIMEOUT_MS,
            abortSignal,
          ),
        );
      }
      if (typecheck.status === 'passed') {
        if (mainModule === undefined) {
          run = errorStage(QUINT_MAIN_REQUIRED_MESSAGE);
        } else if (targetScopeError) {
          run = errorStage(targetScopeError);
        } else {
          const invariantNames = targets.invariants.map(({ name }) => name);
          const runArgs = [
            'run',
            quintPath,
            '--main',
            mainModule,
            '--backend',
            'typescript',
            '--max-samples',
            '1',
            '--max-steps',
            '20',
            '--verbosity',
            '2',
            ...(invariantNames.length > 0 ? ['--invariants', ...invariantNames] : []),
          ];
          const runOutputParser = createQuintRunOutputParser(invariantNames);
          const runProcessResult = await runQuintCommand(
            quintCli,
            runArgs,
            runDirectory,
            QUINT_TIMEOUT_MS,
            abortSignal,
            runOutputParser.consume,
          );
          run = quintRunProcessStage(
            runProcessResult,
            invariantNames,
            runOutputParser.finish(),
          );
        }
      }
      quintStageSet = { parse, typecheck, run };
      quint = quintResultFromStages(quintStageSet, targets);
    }

    const canRunQuintVerify = quintPath !== undefined
      && mainModule !== undefined
      && quint.parse?.status === 'passed'
      && quint.typecheck?.status === 'passed'
      && quint.run?.status === 'passed';
    const javaDetectionRan = alloyPath !== undefined || canRunQuintVerify;
    const detectedJavaMajorVersion = javaDetectionRan
      ? await javaVersion(runDirectory, abortSignal)
      : undefined;
    const hasJava17 = detectedJavaMajorVersion !== undefined && detectedJavaMajorVersion >= 17;
    const javaSkipMessage = alloyPath === undefined
      ? 'Java 17 or later was not detected; Quint verification was skipped.'
      : 'Java 17 or later was not detected; Quint verify and Alloy verification were skipped. Alloy specifications remain unverified.';

    if (canRunQuintVerify && hasJava17 && quintPath !== undefined && mainModule !== undefined) {
      const quintCli = resolveQuintCli();
      const verifyBackend: QuintVerificationBackend = targets.temporal.length > 0 ? 'tlc' : 'apalache';
      const verifyArgs = [
        'verify',
        quintPath,
        '--main',
        mainModule,
        ...(verifyBackend === 'tlc' ? ['--backend', verifyBackend] : []),
        '--max-steps',
        '20',
        ...(verifyBackend === 'tlc' ? [] : ['--verbosity', '0']),
        ...(targets.invariants.length > 0
          ? ['--invariant', targets.invariants.map(({ name }) => name).join(',')]
          : []),
        ...(targets.temporal.length > 0
          ? ['--temporal', targets.temporal.map(({ name }) => name).join(',')]
          : []),
      ];
      const verify = verificationProcessStage(
        await runQuintCommand(quintCli, verifyArgs, runDirectory, modelCheckTimeoutMs, abortSignal),
        verifyBackend,
      );
      if (quintPath) {
        quintStageSet = { ...quintStageSet, verify };
        quint = quintResultFromStages(quintStageSet, targets);
      }
    } else if (quintPath) {
      const message = canRunQuintVerify && javaDetectionRan
        ? javaSkipMessage
        : 'Quint verification was skipped because an earlier Quint stage did not pass.';
      quintStageSet = { ...quintStageSet, verify: skippedStage(message) };
      quint = quintResultFromStages(quintStageSet, targets);
    }
    if (quintPath) {
      stages.push(
        ...[quintStageSet.parse, quintStageSet.typecheck, quintStageSet.run, quintStageSet.verify]
          .filter((stage): stage is FormalSpecStageResult => stage !== undefined),
      );
    }

    let alloy: FormalSpecAlloyResult = skippedAlloyResult('Alloy verification was not run.');
    if (!alloyPath) {
      alloy = skippedAlloyResult('No Alloy specification block was present.');
      stages.push(alloy);
    } else if (!hasJava17) {
      alloy = skippedAlloyResult(javaSkipMessage);
      stages.push(alloy);
    } else {
      let jarPath: string | undefined;
      try {
        jarPath = await ensureAlloyJar(cwd, modelCheckTimeoutMs, abortSignal);
      } catch (error) {
        const message = `Alloy Analyzer could not be prepared: ${error instanceof Error ? error.message : String(error)}`;
        alloy = { status: 'error', message };
        stages.push(alloy);
      }

      if (jarPath !== undefined) {
        const commandsProcess = await runAlloyCommand(
          jarPath,
          ['commands', alloyPath],
          runDirectory,
          modelCheckTimeoutMs,
          abortSignal,
        );
        if (!isSuccessfulProcess(commandsProcess)) {
          alloy = { status: 'error', message: processFailureMessage(commandsProcess) };
          stages.push(alloy);
        } else if (commandsProcess.stdoutTruncated) {
          alloy = { status: 'error', message: ALLOY_COMMAND_OUTPUT_TRUNCATED_MESSAGE };
          stages.push(alloy);
        } else {
          const commands = parseAlloyCommands(commandsProcess.stdout);
          const checkTargets = selectAlloyCheckTargets(commands);
          if (checkTargets.length === 0) {
            alloy = { status: 'error', message: 'Alloy specification contains no check command.', commands };
            stages.push(alloy);
          } else {
            const checkResults: FormalSpecStageResult[] = [];
            for (const commandNumber of checkTargets) {
              const checkProcess = await runAlloyCommand(
                jarPath,
                ['exec', '--quiet', '--type', 'text', '--output', '-', '--command', String(commandNumber), alloyPath],
                runDirectory,
                modelCheckTimeoutMs,
                abortSignal,
              );
              const check = isSuccessfulProcess(checkProcess) && checkProcess.stdout.trim() === ''
                ? passedStage()
                : checkProcess.outcome === 'exit' && checkProcess.status !== null
                  ? failedStage(checkProcess)
                  : errorStage(processFailureMessage(checkProcess));
              checkResults.push(check);
            }
            const primary = aggregateStageResult(checkResults, 'No Alloy check was executed.');
            alloy = {
              status: primary.status,
              ...(primary.message ? { message: primary.message } : {}),
              checks: checkTargets,
              commands,
            };
            stages.push(...checkResults);
          }
        }
      }
    }

    const primary = selectPrimaryStage(stages);
    return {
      verdict: primary.status === 'skipped' ? 'error' : primary.status,
      verificationStarted: true,
      ...(primary.message ? { message: primary.message } : {}),
      ...(detectedJavaMajorVersion === undefined ? {} : { javaMajorVersion: detectedJavaMajorVersion }),
      quint,
      alloy,
    };
  } catch (error) {
    if (abortSignal?.aborted) {
      throw abortSignal.reason ?? error;
    }
    return resultForUnexpectedError(error, verificationStarted);
  } finally {
    if (runDirectory) {
      removeVerifyRunDirectory(runDirectory);
    }
  }
}
