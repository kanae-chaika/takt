import { EventEmitter } from 'node:events';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  rmSync,
  utimesSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const { alloyJarDigestOverride } = vi.hoisted(() => ({
  alloyJarDigestOverride: { value: undefined as string | undefined },
}));

vi.mock('node:crypto', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:crypto')>();
  return {
    ...actual,
    createHash: (...args: Parameters<typeof actual.createHash>) => {
      const digest = alloyJarDigestOverride.value;
      if (digest === undefined) {
        return actual.createHash(...args);
      }
      return {
        update: () => ({ digest: () => digest }),
      } as unknown as ReturnType<typeof actual.createHash>;
    },
  };
});

const { mockSpawnManagedProcess } = vi.hoisted(() => ({
  mockSpawnManagedProcess: vi.fn(),
}));

const { failSpecsDirectoryCreation } = vi.hoisted(() => ({
  failSpecsDirectoryCreation: { enabled: false },
}));

const { failParseJsonRead } = vi.hoisted(() => ({
  failParseJsonRead: { enabled: false },
}));

const { parseJsonReadAttempts } = vi.hoisted(() => ({
  parseJsonReadAttempts: { count: 0 },
}));

const { parseJsonReadMetrics, parseJsonReadChunkSize } = vi.hoisted(() => ({
  parseJsonReadMetrics: { reads: 0, maxRequestedBytes: 0, closes: 0 },
  parseJsonReadChunkSize: { value: undefined as number | undefined },
}));

const { failVerifyRunRemoval, processBoundaryControls } = vi.hoisted(() => ({
  failVerifyRunRemoval: { enabled: false },
  processBoundaryControls: { throwOnSpawn: false },
}));

vi.mock('node:fs', async () => {
  const actual = await vi.importActual<typeof import('node:fs')>('node:fs');
  return {
    ...actual,
    mkdirSync: (...args: Parameters<typeof actual.mkdirSync>) => {
      const target = String(args[0]);
      if (failSpecsDirectoryCreation.enabled && (target.endsWith('/specs') || target.endsWith('\\specs'))) {
        throw new Error('specs directory creation failed');
      }
      return actual.mkdirSync(...args);
    },
    rmSync: (...args: Parameters<typeof actual.rmSync>) => {
      const options = args[1];
      if (failVerifyRunRemoval.enabled
        && typeof options === 'object'
        && options !== null
        && 'recursive' in options
        && options.recursive === true) {
        throw new Error('verify run cleanup failed');
      }
      return actual.rmSync(...args);
    },
  };
});

vi.mock('node:fs/promises', async () => {
  const actual = await vi.importActual<typeof import('node:fs/promises')>('node:fs/promises');
  return {
    ...actual,
    open: async (...args: Parameters<typeof actual.open>) => {
      const isParseJson = String(args[0]).endsWith('parse.json');
      if (isParseJson) {
        parseJsonReadAttempts.count += 1;
      }
      if (failParseJsonRead.enabled && isParseJson) {
        throw new Error('parse JSON read failed');
      }
      const file = await actual.open(...args);
      if (!isParseJson) return file;
      return {
        read: async (buffer: Buffer, offset: number, length: number, position: number | null) => {
          parseJsonReadMetrics.reads += 1;
          parseJsonReadMetrics.maxRequestedBytes = Math.max(parseJsonReadMetrics.maxRequestedBytes, length);
          const chunkLength = parseJsonReadChunkSize.value === undefined
            ? length
            : Math.min(length, parseJsonReadChunkSize.value);
          return file.read(buffer, offset, chunkLength, position);
        },
        close: async () => {
          parseJsonReadMetrics.closes += 1;
          await file.close();
        },
      } as Awaited<ReturnType<typeof actual.open>>;
    },
  };
});

vi.mock('../shared/utils/spawn.js', () => ({
  spawnManagedProcess: (...args: unknown[]) => mockSpawnManagedProcess(...args),
}));

import {
  detectJavaMajorVersion,
  extractFormalSpecBlocks,
  runFormalSpecVerification,
  selectAlloyCheckTargets,
  selectQuintVerificationTargets,
} from '../features/interactive/formalSpecVerifier.js';

const originalAlloyJar = process.env.TAKT_ALLOY_JAR;

interface MockProcessResponse {
  readonly code?: number | null;
  readonly signal?: NodeJS.Signals | null;
  readonly stdout?: string;
  readonly stdoutChunks?: readonly string[];
  readonly stderr?: string;
  readonly error?: Error;
  readonly hang?: boolean;
  readonly beforeExit?: () => Promise<void>;
}

class MockStream extends EventEmitter {
  setEncoding(_encoding: string): void {
    // The runner only needs the stream event contract in these process-boundary tests.
  }
}

const processResponses: MockProcessResponse[] = [];
const spawnedProcesses: Array<{
  readonly command: string;
  readonly args: readonly string[];
  readonly options: { readonly cwd?: string; readonly env?: NodeJS.ProcessEnv };
}> = [];
let parseResult: unknown = {
  modules: [{
    name: 'verify',
    declarations: [
      { kind: 'def', name: 'init', qualifier: 'action' },
      { kind: 'def', name: 'step', qualifier: 'action' },
      { kind: 'def', name: 'invSafe', qualifier: 'val' },
    ],
  }],
};
type ParseOutputOverride =
  | { readonly kind: 'missing' }
  | { readonly kind: 'raw'; readonly content: string };
let parseOutputOverride: ParseOutputOverride | undefined;

const EXPECTED_ALLOY_JAR_SHA256 = '6037cbeee0e8423c1c468447ed10f5fcf2f2743a2ffc39cb1c81f2905c0fdb9d';

function installConfiguredAlloyJar(directory: string): void {
  const jarPath = join(directory, 'alloy-fixture.jar');
  writeFileSync(jarPath, Buffer.from([0x50, 0x4b, 0x03, 0x04]), { mode: 0o600 });
  process.env.TAKT_ALLOY_JAR = jarPath;
}

function mockProcessBoundary(): void {
  mockSpawnManagedProcess.mockImplementation((
    command: string,
    args: readonly string[],
    options: { readonly cwd?: string; readonly env?: NodeJS.ProcessEnv },
    signal: AbortSignal,
  ) => {
    spawnedProcesses.push({ command, args, options });
    if (processBoundaryControls.throwOnSpawn) {
      throw new Error('spawn failed synchronously');
    }
    const response = processResponses.shift() ?? { code: 0 };
    const stdout = new MockStream();
    const stderr = new MockStream();
    const parseOutputIndex = args.indexOf('--out');
    if (parseOutputIndex >= 0) {
      const parseOutputPath = args[parseOutputIndex + 1];
      if (parseOutputPath !== undefined && parseOutputOverride?.kind !== 'missing') {
        const content = parseOutputOverride?.kind === 'raw'
          ? parseOutputOverride.content
          : JSON.stringify(parseResult);
        writeFileSync(parseOutputPath, content);
      }
    }
    const wait = async () => {
      await response.beforeExit?.();
      if (response.stdoutChunks !== undefined) {
        for (const chunk of response.stdoutChunks) stdout.emit('data', chunk);
      } else if (response.stdout !== undefined) {
        stdout.emit('data', response.stdout);
      }
      if (response.stderr !== undefined) stderr.emit('data', response.stderr);
      if (response.hang) {
        await new Promise<never>((_resolve, reject) => {
          signal.addEventListener('abort', () => reject(signal.reason), { once: true });
        });
      }
      if (response.error !== undefined) throw response.error;
      return {
        code: response.code === undefined ? 0 : response.code,
        signal: response.signal ?? null,
      };
    };
    return {
      child: { stdout, stderr },
      wait,
      waitForExit: wait,
    };
  });
}

function createTestDirectory(): string {
  return mkdtempSync(join(tmpdir(), 'takt-formal-spec-unit-'));
}

function validAlloyResponse(): string {
  return ['```alloy', 'sig A {}', 'check Safety for 1', '```'].join('\n');
}

function mockTlcVerification(response: MockProcessResponse): void {
  parseResult = {
    modules: [{
      name: 'workflowModel',
      declarations: [
        { kind: 'def', name: 'init', qualifier: 'action' },
        { kind: 'def', name: 'step', qualifier: 'action' },
        { kind: 'def', name: 'propEventually', qualifier: 'temporal' },
      ],
    }],
  };
  processResponses.push(
    { code: 0 },
    { code: 0 },
    { code: 0 },
    { code: 0, stderr: 'openjdk version "17.0.1"' },
    response,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  processResponses.length = 0;
  spawnedProcesses.length = 0;
  parseResult = {
    modules: [{
      name: 'verify',
      declarations: [
        { kind: 'def', name: 'init', qualifier: 'action' },
        { kind: 'def', name: 'step', qualifier: 'action' },
        { kind: 'def', name: 'invSafe', qualifier: 'val' },
      ],
    }],
  };
  parseOutputOverride = undefined;
  failSpecsDirectoryCreation.enabled = false;
  failParseJsonRead.enabled = false;
  parseJsonReadAttempts.count = 0;
  parseJsonReadMetrics.reads = 0;
  parseJsonReadMetrics.maxRequestedBytes = 0;
  parseJsonReadMetrics.closes = 0;
  parseJsonReadChunkSize.value = undefined;
  failVerifyRunRemoval.enabled = false;
  processBoundaryControls.throwOnSpawn = false;
  alloyJarDigestOverride.value = undefined;
  delete process.env.TAKT_ALLOY_JAR;
  mockProcessBoundary();
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  failSpecsDirectoryCreation.enabled = false;
  alloyJarDigestOverride.value = undefined;
  if (originalAlloyJar === undefined) {
    delete process.env.TAKT_ALLOY_JAR;
  } else {
    process.env.TAKT_ALLOY_JAR = originalAlloyJar;
  }
});

describe('runFormalSpecVerification', () => {
  const largeInvariantNames = Array.from(
    { length: 600 },
    (_, index) => `invFailure${String(index).padStart(4, '0')}`,
  );

  function setLargeInvariantParseResult(): void {
    parseResult = {
      modules: [{
        name: 'verify',
        declarations: [
          { kind: 'def', name: 'init', qualifier: 'action' },
          { kind: 'def', name: 'step', qualifier: 'action' },
          ...largeInvariantNames.map((name) => ({ kind: 'def', name, qualifier: 'val' })),
        ],
      }],
    };
  }

  function largeInvariantOutput(): string {
    return [
      'An example execution:',
      'State 0',
      '{ counter: 0 }',
      '[violation] Found an issue',
      ...largeInvariantNames.map((name) => `  ❌ ${name}`),
    ].join('\n');
  }

  it('should fail explicitly without invoking verification when the response has no target blocks', async () => {
    const result = await runFormalSpecVerification('No formal specification was generated.', '/repo', { modelCheckTimeoutSeconds: 300 });

    expect(result).toEqual({
      verdict: 'error',
      verificationStarted: false,
      message: 'No formal specification blocks found.',
      quint: {
        status: 'skipped',
        message: 'No formal specification blocks found.',
      },
      alloy: {
        status: 'skipped',
        message: 'No formal specification blocks found.',
      },
    });
  });

  it('should include every Quint parse diagnostic and source position after a parse failure', async () => {
    const directory = createTestDirectory();
    parseResult = {
      errors: [
        {
          explanation: '[QNT101] First parse diagnostic',
          locs: [
            { source: '/tmp/spec.qnt', start: { line: 2, col: 2 } },
            { source: '/tmp/shared.qnt', start: { line: 4, col: 6 } },
          ],
        },
        {
          explanation: '[QNT202] Second parse diagnostic',
          locs: [{ source: '/tmp/spec.qnt', start: { line: 7, col: 3 } }],
        },
      ],
    };
    processResponses.push({ code: 1 });

    try {
      const result = await runFormalSpecVerification('```quint\nmodule invalid {}\n```', directory, { modelCheckTimeoutSeconds: 300 });
      const message = result.quint.parse?.message ?? '';

      expect(result.quint.parse?.status).toBe('error');
      expect(message).toContain('[QNT101] First parse diagnostic');
      expect(message).toContain('[QNT202] Second parse diagnostic');
      expect(message.indexOf('[QNT101] First parse diagnostic'))
        .toBeLessThan(message.indexOf('[QNT202] Second parse diagnostic'));
      expect(message).toContain('spec.qnt:3:3');
      expect(message).toContain('shared.qnt:5:7');
      expect(message).toContain('spec.qnt:8:4');
      expect(result.quint.typecheck?.status).toBe('skipped');
      expect(result.quint.run?.status).toBe('skipped');
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it.each([
    {
      name: 'missing parse JSON with no process output',
      parseOutput: { kind: 'missing' as const },
      response: { code: 1 },
      expectedMessage: 'Process exited with status 1',
    },
    {
      name: 'malformed parse JSON with both process streams',
      parseOutput: { kind: 'raw' as const, content: '{"errors":[' },
      response: { code: 1, stderr: 'parse stderr', stdout: 'parse stdout' },
      expectedMessage: 'parse stderr\nparse stdout',
      assertParseJsonReadAttempt: true,
    },
    {
      name: 'display-budget diagnostics followed by malformed JSON data',
      parseOutput: {
        kind: 'raw' as const,
        content: `${JSON.stringify({
          errors: [{
            locs: [{ source: '/tmp/spec.qnt', start: { line: 2, col: 2 } }],
            explanation: `[QNT101] ${'x'.repeat(9_000)}`,
          }],
        })}x`,
      },
      response: { code: 1, stderr: 'parse failed' },
      expectedMessage: 'parse failed',
      assertParseJsonReadAttempt: true,
    },
    {
      name: 'unreadable parse JSON with process output',
      failParseJsonRead: true,
      response: { code: 1, stderr: 'parse stderr' },
      expectedMessage: 'parse stderr',
      assertParseJsonReadAttempt: true,
    },
    {
      name: 'an empty root errors array with nested and quoted errors',
      parseResult: {
        errors: [],
        modules: [{ errors: [{ explanation: 'nested fake diagnostic' }] }],
        note: '"errors":[{"explanation":"quoted fake diagnostic"}]',
      },
      response: { code: 1, stderr: 'parse failed' },
      expectedMessage: 'parse failed',
      assertParseJsonReadAttempt: true,
    },
    {
      name: 'a root errors field with the wrong type',
      parseResult: { errors: 'not an array' },
      response: { code: 1, stderr: 'parse failed' },
      expectedMessage: 'parse failed',
      assertParseJsonReadAttempt: true,
    },
    {
      name: 'a malformed root diagnostic after a long diagnostic',
      parseResult: {
        errors: [
          {
            explanation: `[QNT999] ${'x'.repeat(9_000)}`,
            locs: [{ source: '/tmp/spec.qnt', start: { line: 2, col: 2 } }],
          },
          { explanation: '[QNT101] Invalid location', locs: [{ source: '/tmp/spec.qnt', start: { line: -1, col: 2 } }] },
        ],
      },
      response: { code: 1, stderr: 'parse failed' },
      expectedMessage: 'parse failed',
      assertParseJsonReadAttempt: true,
    },
  ])('should use the process failure message for $name', async ({ parseOutput, parseResult: output, failParseJsonRead: readFailure, response, expectedMessage, assertParseJsonReadAttempt }) => {
    const directory = createTestDirectory();
    if (parseOutput !== undefined) {
      parseOutputOverride = parseOutput;
    }
    if (readFailure === true) {
      failParseJsonRead.enabled = true;
    }
    if (output !== undefined) {
      parseResult = output;
    }
    processResponses.push(response);

    try {
      const result = await runFormalSpecVerification('```quint\nmodule invalid {}\n```', directory, { modelCheckTimeoutSeconds: 300 });

      expect(result.quint.parse).toEqual({ status: 'error', message: expectedMessage });
      expect(result.quint.typecheck?.status).toBe('skipped');
      expect(result.quint.run?.status).toBe('skipped');
      expect(spawnedProcesses.map(({ args }) => args[1])).toEqual(['parse']);
      if (assertParseJsonReadAttempt === true) {
        expect(parseJsonReadAttempts.count).toBeGreaterThan(0);
        expect(parseJsonReadMetrics.closes).toBe(readFailure === true ? 0 : 1);
      }
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('should parse split UTF-8 and escaped JSON input with fields in any order', async () => {
    const directory = createTestDirectory();
    parseJsonReadChunkSize.value = 1;
    parseResult = {
      errors: [{
        locs: [{ source: '/tmp/spec.qnt', start: { col: 12, line: 20 } }],
        explanation: '[QNT101] 雪\\n"invalid"',
      }],
    };
    processResponses.push({ code: 1, stderr: 'parse failed' });

    try {
      const result = await runFormalSpecVerification('```quint\nmodule invalid {}\n```', directory, { modelCheckTimeoutSeconds: 300 });

      expect(result.quint.parse?.status).toBe('error');
      expect(result.quint.parse?.message).toBe('spec.qnt:21:13: [QNT101] 雪\\n"invalid"');
      expect(parseJsonReadMetrics.reads).toBeGreaterThan(1);
      expect(parseJsonReadMetrics.closes).toBe(1);
      expect(result.quint.typecheck?.status).toBe('skipped');
      expect(result.quint.run?.status).toBe('skipped');
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('should stream large unrelated values and long source paths while retaining only bounded diagnostics', async () => {
    const directory = createTestDirectory();
    const locations = Array.from({ length: 1_500 }, (_, index) => ({
      source: index === 0 ? `/tmp/${'x'.repeat(100_000)}/spec.qnt` : `/tmp/spec-${index}.qnt`,
      start: { line: index, col: index },
    }));
    parseResult = {
      unrelated: { note: 'x'.repeat(150_000) },
      errors: [{
        locs: locations,
        explanation: '[QNT101] bounded diagnostic',
      }],
    };
    processResponses.push({ code: 1 });

    try {
      const result = await runFormalSpecVerification('```quint\nmodule invalid {}\n```', directory, { modelCheckTimeoutSeconds: 300 });
      const message = result.quint.parse?.message ?? '';

      expect(result.quint.parse?.status).toBe('error');
      expect(message).toMatch(/^spec\.qnt:1:1, spec-1\.qnt:2:2, spec-2\.qnt:3:3/u);
      expect(message).toContain('[QNT101] bounded diagnostic');
      expect(message.length).toBeLessThanOrEqual(8_000);
      expect(message.endsWith('他 0 件の診断を省略')).toBe(true);
      expect(parseJsonReadMetrics.maxRequestedBytes).toBe(64 * 1024);
      expect(parseJsonReadMetrics.reads).toBeGreaterThan(1);
      expect(parseJsonReadMetrics.closes).toBe(1);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('should keep the first long Quint parse diagnostic and report omitted diagnostics', async () => {
    const directory = createTestDirectory();
    parseResult = {
      errors: [
        {
          explanation: `[QNT999] ${'x'.repeat(9_000)}`,
          locs: [{ source: '/tmp/spec.qnt', start: { line: 2, col: 2 } }],
        },
        {
          explanation: '[QNT101] Second parse diagnostic',
          locs: [{ source: '/tmp/spec.qnt', start: { line: 4, col: 2 } }],
        },
        {
          explanation: '[QNT202] Third parse diagnostic',
          locs: [{ source: '/tmp/spec.qnt', start: { line: 6, col: 2 } }],
        },
      ],
    };
    processResponses.push({ code: 1 });

    try {
      const result = await runFormalSpecVerification('```quint\nmodule invalid {}\n```', directory, { modelCheckTimeoutSeconds: 300 });
      const message = result.quint.parse?.message ?? '';

      expect(result.quint.parse?.status).toBe('error');
      expect(message.startsWith('spec.qnt:3:3: [QNT999] ')).toBe(true);
      expect(message.length).toBeLessThanOrEqual(8_000);
      expect(message).toContain('x'.repeat(64));
      expect(message).toContain('[output truncated]');
      expect(message.endsWith('他 2 件の診断を省略')).toBe(true);
      expect(message).not.toContain('[QNT101] Second parse diagnostic');
      expect(message).not.toContain('[QNT202] Third parse diagnostic');
      expect(result.quint.typecheck?.status).toBe('skipped');
      expect(result.quint.run?.status).toBe('skipped');
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('should keep complete parse diagnostics in order when their combined length exceeds the limit', async () => {
    const directory = createTestDirectory();
    const firstLocationPrefix = 'spec.qnt:3:3: ';
    const secondLocationPrefix = 'spec.qnt:5:3: ';
    const thirdLocationPrefix = 'spec.qnt:7:3: ';
    const firstExplanation = `[QNT101] ${'a'.repeat(3_900 - firstLocationPrefix.length - '[QNT101] '.length)}`;
    const secondExplanation = `[QNT202] ${'b'.repeat(3_900 - secondLocationPrefix.length - '[QNT202] '.length)}`;
    const thirdExplanation = `[QNT303] ${'c'.repeat(300 - thirdLocationPrefix.length - '[QNT303] '.length)}`;
    const firstDiagnostic = `${firstLocationPrefix}${firstExplanation}`;
    const secondDiagnostic = `${secondLocationPrefix}${secondExplanation}`;
    const thirdDiagnostic = `${thirdLocationPrefix}${thirdExplanation}`;
    parseResult = {
      errors: [
        {
          explanation: firstExplanation,
          locs: [{ source: '/tmp/spec.qnt', start: { line: 2, col: 2 } }],
        },
        {
          explanation: secondExplanation,
          locs: [{ source: '/tmp/spec.qnt', start: { line: 4, col: 2 } }],
        },
        {
          explanation: thirdExplanation,
          locs: [{ source: '/tmp/spec.qnt', start: { line: 6, col: 2 } }],
        },
      ],
    };
    processResponses.push({ code: 1 });

    try {
      const result = await runFormalSpecVerification('```quint\nmodule invalid {}\n```', directory, { modelCheckTimeoutSeconds: 300 });
      const message = result.quint.parse?.message ?? '';

      expect(firstDiagnostic).toHaveLength(3_900);
      expect(secondDiagnostic).toHaveLength(3_900);
      expect(thirdDiagnostic).toHaveLength(300);
      expect(message).toBe(`${firstDiagnostic}\n${secondDiagnostic}\n他 1 件の診断を省略`);
      expect(message.length).toBeLessThanOrEqual(8_000);
      expect(result.quint.parse?.status).toBe('error');
      expect(result.quint.typecheck?.status).toBe('skipped');
      expect(result.quint.run?.status).toBe('skipped');
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it.each([8_000, 8_001])('should keep the source position at a diagnostic body length of %i characters', async (bodyLength) => {
    const directory = createTestDirectory();
    const locationPrefix = 'spec.qnt:3:3: ';
    const diagnosticPrefix = '[QNT999] ';
    parseResult = {
      errors: [{
        explanation: `${diagnosticPrefix}${'x'.repeat(bodyLength - locationPrefix.length - diagnosticPrefix.length)}`,
        locs: [{ source: '/tmp/spec.qnt', start: { line: 2, col: 2 } }],
      }],
    };
    processResponses.push({ code: 1 });

    try {
      const result = await runFormalSpecVerification('```quint\nmodule invalid {}\n```', directory, { modelCheckTimeoutSeconds: 300 });
      const message = result.quint.parse?.message ?? '';

      expect(result.quint.parse?.status).toBe('error');
      expect(message.startsWith(`${locationPrefix}${diagnosticPrefix}`)).toBe(true);
      if (bodyLength === 8_000) {
        expect(message).toHaveLength(8_000);
        expect(message).not.toContain('[output truncated]');
      } else {
        expect(message.length).toBeLessThanOrEqual(8_000);
        expect(message).toContain('[output truncated]');
        expect(message.endsWith('他 0 件の診断を省略')).toBe(true);
      }
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('should name only the violated invariant in a failed Quint run message', async () => {
    const directory = createTestDirectory();
    parseResult = {
      modules: [{
        name: 'verify',
        declarations: [
          { kind: 'def', name: 'init', qualifier: 'action' },
          { kind: 'def', name: 'step', qualifier: 'action' },
          { kind: 'def', name: 'invSmall', qualifier: 'val' },
          { kind: 'def', name: 'invNonNegative', qualifier: 'val' },
        ],
      }],
    };
    processResponses.push(
      { code: 0 },
      { code: 0 },
      {
        code: 1,
        stderr: 'error: Invariant violated',
        stdout: '\u001b[2mAn example execution:\u001b[0m\nState 0\n{ counter: 0 }\n\u001b[31m[violation]\u001b[0m Found an issue\n\u001b[31m  ❌ invSmall\u001b[0m\n',
      },
    );

    try {
      const result = await runFormalSpecVerification('```quint\nmodule verify {}\n```', directory, { modelCheckTimeoutSeconds: 300 });
      const runCall = spawnedProcesses.find(({ args }) => args.includes('run'));
      const verbosityIndex = runCall?.args.indexOf('--verbosity') ?? -1;
      const verbosity = Number(runCall?.args[verbosityIndex + 1]);
      const runMessage = result.quint.run?.message ?? '';

      expect(result.quint.run?.status).toBe('failed');
      expect(result.message).toContain('invSmall');
      expect(result.message).not.toContain('invNonNegative');
      expect(runMessage.indexOf('❌ invSmall')).toBeLessThan(runMessage.indexOf('State 0'));
      expect(verbosity).toBe(2);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('should retain a short counterexample trace when the violated invariant names exceed the message budget', async () => {
    const directory = createTestDirectory();
    setLargeInvariantParseResult();
    processResponses.push(
      { code: 0 },
      { code: 0 },
      {
        code: 1,
        stderr: 'error: Invariant violated',
        stdout: largeInvariantOutput(),
      },
    );

    try {
      const result = await runFormalSpecVerification('```quint\nmodule verify {}\n```', directory, { modelCheckTimeoutSeconds: 300 });
      const message = result.quint.run?.message ?? '';
      const firstViolationName = '❌ invFailure0000';

      expect(result.quint.run?.status).toBe('failed');
      expect(message.length).toBeLessThanOrEqual(8_000);
      expect(message).toContain(firstViolationName);
      expect(message).toContain('An example execution:\nState 0\n{ counter: 0 }');
      expect(message.indexOf(firstViolationName)).toBeLessThan(message.indexOf('State 0'));
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('should not prefix violated invariant names from stdout for a general run error', async () => {
    const directory = createTestDirectory();
    setLargeInvariantParseResult();
    processResponses.push(
      { code: 0 },
      { code: 0 },
      {
        code: 1,
        stderr: 'error: Runtime error',
        stdout: largeInvariantOutput(),
      },
    );

    try {
      const result = await runFormalSpecVerification('```quint\nmodule verify {}\n```', directory, { modelCheckTimeoutSeconds: 300 });
      const message = result.quint.run?.message ?? '';

      expect(result.quint.run?.status).toBe('failed');
      expect(message.startsWith('error: Runtime error\nAn example execution:')).toBe(true);
      expect(message.indexOf('State 0')).toBeLessThan(message.indexOf('❌ invFailure0000'));
      expect(message).toContain('State 0');
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('should parse a violation header and name split across stdout chunks', async () => {
    const directory = createTestDirectory();
    parseResult = {
      modules: [{
        name: 'verify',
        declarations: [
          { kind: 'def', name: 'init', qualifier: 'action' },
          { kind: 'def', name: 'step', qualifier: 'action' },
          { kind: 'def', name: 'invSmall', qualifier: 'val' },
          { kind: 'def', name: 'invNonNegative', qualifier: 'val' },
        ],
      }],
    };
    processResponses.push(
      { code: 0 },
      { code: 0 },
      {
        code: 1,
        stderr: 'error: Invariant violated',
        stdoutChunks: [
          'State 0\r\n{ counter: 0 }\r\n[viol',
          'ation] Found an issue\r\n  \u001b[3',
          '1m❌ invSm',
          'all\u001b[0m',
        ],
      },
    );

    try {
      const result = await runFormalSpecVerification('```quint\nmodule verify {}\n```', directory, { modelCheckTimeoutSeconds: 300 });
      const message = result.quint.run?.message ?? '';

      expect(result.quint.run?.status).toBe('failed');
      expect(message.indexOf('❌ invSmall')).toBeLessThan(message.indexOf('State 0'));
      expect(message).toContain('{ counter: 0 }');
      expect(message).not.toContain('invNonNegative');
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('should collect violated names across debug lines and stop at the Quint result terminator', async () => {
    const directory = createTestDirectory();
    parseResult = {
      modules: [{
        name: 'verify',
        declarations: [
          { kind: 'def', name: 'init', qualifier: 'action' },
          { kind: 'def', name: 'step', qualifier: 'action' },
          { kind: 'def', name: 'invSmall', qualifier: 'val' },
          { kind: 'def', name: 'invOther', qualifier: 'val' },
          { kind: 'def', name: 'invNonNegative', qualifier: 'val' },
        ],
      }],
    };
    processResponses.push(
      { code: 0 },
      { code: 0 },
      {
        code: 1,
        stderr: 'error: Invariant violated',
        stdoutChunks: [
          'State 0\r\n{ counter: 0 }\r\n[violation] Found an issue\r\n> "first" false\r\n  ❌ invUnknown\r\n  ❌ invSmall\r\n',
          `> "second" false\r\n${'long debug output '.repeat(100)}\r\n  ❌ invSmall\r\n  ❌ invOther\r\nUse --verbosity=3 to show `,
          'executions.\r\n  ❌ invNonNegative\r\n',
        ],
      },
    );

    try {
      const result = await runFormalSpecVerification('```quint\nmodule verify {}\n```', directory, { modelCheckTimeoutSeconds: 300 });
      const message = result.quint.run?.message ?? '';

      expect(result.quint.run?.status).toBe('failed');
      expect(message.startsWith('❌ invSmall\n❌ invOther\nerror: Invariant violated\n')).toBe(true);
      expect(message.indexOf('❌ invSmall')).toBeLessThan(message.indexOf('❌ invOther'));
      expect(message.indexOf('❌ invOther')).toBeLessThan(message.indexOf('State 0'));
      expect(message.slice(0, message.indexOf('error: Invariant violated'))).toBe('❌ invSmall\n❌ invOther\n');
      expect(message).toContain('long debug output');
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('should detect a violated invariant after the output limit before formatting the run message', async () => {
    const directory = createTestDirectory();
    parseResult = {
      modules: [{
        name: 'verify',
        declarations: [
          { kind: 'def', name: 'init', qualifier: 'action' },
          { kind: 'def', name: 'step', qualifier: 'action' },
          { kind: 'def', name: 'invSmall', qualifier: 'val' },
          { kind: 'def', name: 'invNonNegative', qualifier: 'val' },
        ],
      }],
    };
    processResponses.push(
      { code: 0 },
      { code: 0 },
      {
        code: 1,
        stderr: 'error: Invariant violated',
        stdout: `An example execution:\nState 0\n{ counter: 0 }\n${'x'.repeat(9_000)}\n[violation] Found an issue\n  ❌ invSmall\n`,
      },
    );

    try {
      const result = await runFormalSpecVerification('```quint\nmodule verify {}\n```', directory, { modelCheckTimeoutSeconds: 300 });
      const message = result.quint.run?.message ?? '';
      const trace = `An example execution:\nState 0\n{ counter: 0 }\n${'x'.repeat(9_000)}`;
      const fixedMessage = '❌ invSmall\nerror: Invariant violated';
      const traceBudget = 8_000 - fixedMessage.length - 1 - '\n[output truncated]'.length;
      const expectedMessage = `${fixedMessage}\n${trace.slice(0, traceBudget)}\n[output truncated]`;

      expect(result.quint.run?.status).toBe('failed');
      expect(message).toBe(expectedMessage);
      expect(message).not.toContain('invNonNegative');
      expect(message).toHaveLength(8_000);
      expect(message).toContain('error: Invariant violated');
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it.each([
    { label: 'confirmed invariant violation', stderr: 'error: Invariant violated', includesViolationName: true },
    { label: 'general runtime error', stderr: 'error: Runtime error', includesViolationName: false },
  ])('should retain the violation name after stdout capture overflow only for a $label', async ({ stderr, includesViolationName }) => {
    const directory = createTestDirectory();
    parseResult = {
      modules: [{
        name: 'verify',
        declarations: [
          { kind: 'def', name: 'init', qualifier: 'action' },
          { kind: 'def', name: 'step', qualifier: 'action' },
          { kind: 'def', name: 'invSmall', qualifier: 'val' },
          { kind: 'def', name: 'invNonNegative', qualifier: 'val' },
        ],
      }],
    };
    processResponses.push(
      { code: 0 },
      { code: 0 },
      {
        code: 1,
        stderr,
        stdoutChunks: [
          'State 0\n{ counter: 0 }\n',
          'x'.repeat(1_048_577),
          '\n[violation] Found an issue\n  ❌ invSmall\n',
        ],
      },
    );

    try {
      const result = await runFormalSpecVerification('```quint\nmodule verify {}\n```', directory, { modelCheckTimeoutSeconds: 300 });
      const message = result.quint.run?.message ?? '';

      expect(result.quint.run?.status).toBe('failed');
      expect(message).toContain('State 0');
      expect(message).toContain('{ counter: 0 }');
      expect(message.length).toBeLessThanOrEqual(8_000);
      if (includesViolationName) {
        expect(message.indexOf('❌ invSmall')).toBeLessThan(message.indexOf('State 0'));
        expect(message).not.toContain('invNonNegative');
        expect(message).toHaveLength(8_000);
      } else {
        expect(message).toContain('error: Runtime error');
        expect(message).not.toContain('invSmall');
      }
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('should abbreviate the single invariant fallback name without changing the run argument', async () => {
    const directory = createTestDirectory();
    const invariantName = `inv${'x'.repeat(8_000)}`;
    parseResult = {
      modules: [{
        name: 'verify',
        declarations: [
          { kind: 'def', name: 'init', qualifier: 'action' },
          { kind: 'def', name: 'step', qualifier: 'action' },
          { kind: 'def', name: invariantName, qualifier: 'val' },
        ],
      }],
    };
    processResponses.push(
      { code: 0 },
      { code: 0 },
      {
        code: 1,
        stderr: 'error: Invariant violated\n',
        stdout: '[violation] Found an issue\n',
      },
    );

    try {
      const result = await runFormalSpecVerification('```quint\nmodule verify {}\n```', directory, { modelCheckTimeoutSeconds: 300 });
      const runMessage = result.quint.run?.message ?? '';
      const runCall = spawnedProcesses.find(({ args }) => args.includes('run'));

      expect(result.quint.run?.status).toBe('failed');
      expect(runMessage.startsWith('❌ inv')).toBe(true);
      expect(runMessage).toContain('[invariant name truncated]');
      expect(runMessage).not.toContain(invariantName);
      expect(runMessage).toContain('error: Invariant violated');
      expect(runMessage.length).toBeLessThanOrEqual(8_000);
      expect(runMessage).not.toContain('[output truncated]');
      expect(runMessage).not.toContain('[violation] Found an issue');
      expect(result.quint.invariants).toEqual([invariantName]);
      expect(runCall?.args).toContain(invariantName);
      expect(result.message).toContain('[invariant name truncated]');
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('should preserve the short trace when a parsed invariant name is abbreviated', async () => {
    const directory = createTestDirectory();
    const invariantName = `inv${'x'.repeat(8_000)}`;
    const trace = 'An example execution:\nState 0\n{ counter: 0 }';
    parseResult = {
      modules: [{
        name: 'verify',
        declarations: [
          { kind: 'def', name: 'init', qualifier: 'action' },
          { kind: 'def', name: 'step', qualifier: 'action' },
          { kind: 'def', name: invariantName, qualifier: 'val' },
        ],
      }],
    };
    processResponses.push(
      { code: 0 },
      { code: 0 },
      {
        code: 1,
        stderr: 'error: Invariant violated',
        stdout: `${trace}\n[violation] Found an issue\n  ❌ ${invariantName}\n`,
      },
    );

    try {
      const result = await runFormalSpecVerification('```quint\nmodule verify {}\n```', directory, { modelCheckTimeoutSeconds: 300 });
      const message = result.quint.run?.message ?? '';
      const runCall = spawnedProcesses.find(({ args }) => args.includes('run'));

      expect(result.quint.run?.status).toBe('failed');
      expect(message.length).toBeLessThanOrEqual(8_000);
      expect(message.startsWith('❌ inv')).toBe(true);
      expect(message).toContain('[invariant name truncated]');
      expect(message).not.toContain(invariantName);
      expect(message).toContain(trace);
      expect(message.indexOf('[invariant name truncated]')).toBeLessThan(message.indexOf('State 0'));
      expect(result.quint.invariants).toEqual([invariantName]);
      expect(runCall?.args).toContain(invariantName);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('should preserve the complete invariant name and available trace at message boundaries', async () => {
    const trace = 'An example execution:\nState 0\n{ counter: 0 }';
    const boundaryNameLengths = [7_952, 7_953, 7_972, 7_973];

    const verifyWithName = async (invariantName: string, stdout: string) => {
      const directory = createTestDirectory();
      parseResult = {
        modules: [{
          name: 'verify',
          declarations: [
            { kind: 'def', name: 'init', qualifier: 'action' },
            { kind: 'def', name: 'step', qualifier: 'action' },
            { kind: 'def', name: invariantName, qualifier: 'val' },
          ],
        }],
      };
      processResponses.push(
        { code: 0 },
        { code: 0 },
        {
          code: 1,
          stderr: 'error: Invariant violated',
          stdout,
        },
      );

      try {
        const result = await runFormalSpecVerification('```quint\nmodule verify {}\n```', directory, { modelCheckTimeoutSeconds: 300 });
        return {
          status: result.quint.run?.status,
          message: result.quint.run?.message ?? '',
        };
      } finally {
        rmSync(directory, { recursive: true, force: true });
      }
    };

    for (const invariantNameLength of boundaryNameLengths) {
      const invariantName = `inv${'x'.repeat(invariantNameLength - 3)}`;
      const { status, message } = await verifyWithName(
        invariantName,
        `${trace}\n[violation] Found an issue\n  ❌ ${invariantName}\n`,
      );
      const retainedTraceLength = Math.max(0, Math.min(trace.length, 8_000 - invariantNameLength - 1));
      const expectedMessage = invariantNameLength === 8_000
        ? invariantName
        : `${invariantName}\n${trace.slice(0, retainedTraceLength)}`;

      expect(status).toBe('failed');
      expect(message.length).toBeLessThanOrEqual(8_000);
      expect(message).toBe(expectedMessage);
      expect(message.slice(0, invariantNameLength)).toBe(invariantName);
      expect(message.slice(invariantNameLength + 1)).toBe(trace.slice(0, retainedTraceLength));
    }

    const invariantName = `inv${'x'.repeat(7_997)}`;
    const { status, message } = await verifyWithName(invariantName, '');

    expect(status).toBe('failed');
    expect(message).toBe(invariantName);
  });

  it.each([
    {
      label: 'a name beyond the message budget',
      invariantName: `inv${'x'.repeat(8_000)}`,
      stdout: '',
    },
    {
      label: 'a name beyond the previous truncation-note boundary',
      invariantName: `inv${'x'.repeat(7_950)}`,
      stdout: '',
    },
    {
      label: 'a name at the 7,973-character boundary present in stdout',
      invariantName: `inv${'x'.repeat(7_970)}`,
      stdout: `An example execution:\nState 0\n{ counter: 0 }\n[violation] Found an issue\n  ❌ inv${'x'.repeat(7_970)}`,
    },
  ])('should use general formatting for a run error mentioning invariant violation ($label)', async ({ invariantName, stdout }) => {
    const directory = createTestDirectory();
    parseResult = {
      modules: [{
        name: 'verify',
        declarations: [
          { kind: 'def', name: 'init', qualifier: 'action' },
          { kind: 'def', name: 'step', qualifier: 'action' },
          { kind: 'def', name: invariantName, qualifier: 'val' },
        ],
      }],
    };
    const stderr = 'Runtime detail: error: Invariant violated\nerror: Runtime error\n';
    processResponses.push(
      { code: 0 },
      { code: 0 },
      { code: 1, stderr, stdout },
    );

    try {
      const result = await runFormalSpecVerification('```quint\nmodule verify {}\n```', directory, { modelCheckTimeoutSeconds: 300 });
      const runMessage = result.quint.run?.message ?? '';

      expect(result.quint.run?.status).toBe('failed');
      expect(runMessage.startsWith(stderr.trim())).toBe(true);
      expect(runMessage.startsWith(`❌ ${invariantName}`)).toBe(false);
      expect(runMessage).not.toContain('[invariant name truncated]');
      if (stdout.length === 0) {
        expect(runMessage).not.toContain(invariantName);
      } else {
        expect(runMessage).toContain('An example execution:');
        expect(runMessage).not.toContain(invariantName);
      }
      expect(result.message).toContain('Runtime detail: error: Invariant violated');
      expect(result.message).toContain('error: Runtime error');
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('should not treat a stdout match as the Quint invariant violation diagnostic', async () => {
    const directory = createTestDirectory();
    parseResult = {
      modules: [{
        name: 'verify',
        declarations: [
          { kind: 'def', name: 'init', qualifier: 'action' },
          { kind: 'def', name: 'step', qualifier: 'action' },
          { kind: 'def', name: 'invSmall', qualifier: 'val' },
          { kind: 'def', name: 'invNonNegative', qualifier: 'val' },
        ],
      }],
    };
    const stderr = 'error: Runtime error\n';
    const stdout = 'An example execution:\nState 0\n{ counter: 0 }\n[violation] Found an issue\n  ❌ invSmall\n';
    processResponses.push(
      { code: 0 },
      { code: 0 },
      { code: 1, stderr, stdout },
    );

    try {
      const result = await runFormalSpecVerification('```quint\nmodule verify {}\n```', directory, { modelCheckTimeoutSeconds: 300 });
      const runMessage = result.quint.run?.message ?? '';

      expect(result.quint.run?.status).toBe('failed');
      expect(runMessage).toBe(`${stderr.trim()}\n${stdout.trim()}`);
      expect(runMessage.startsWith('❌')).toBe(false);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('should not add an invariant name when the run has no invariant targets', async () => {
    const directory = createTestDirectory();
    parseResult = {
      modules: [{
        name: 'verify',
        declarations: [
          { kind: 'def', name: 'init', qualifier: 'action' },
          { kind: 'def', name: 'step', qualifier: 'action' },
        ],
      }],
    };
    processResponses.push(
      { code: 0 },
      { code: 0 },
      { code: 1, stderr: 'error: Invariant violated\n' },
    );

    try {
      const result = await runFormalSpecVerification('```quint\nmodule verify {}\n```', directory, { modelCheckTimeoutSeconds: 300 });

      expect(result.quint.run?.status).toBe('failed');
      expect(result.quint.run?.message).toBe('error: Invariant violated');
      expect(result.quint.run?.message).not.toContain('❌');
      expect(result.quint.run?.message).not.toContain('[invariant name truncated]');
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it.each([8_000, 8_001])('should cut only the trace tail when the complete name and trace reach %i characters', async (bodyLength) => {
    const directory = createTestDirectory();
    parseResult = {
      modules: [{
        name: 'verify',
        declarations: [
          { kind: 'def', name: 'init', qualifier: 'action' },
          { kind: 'def', name: 'step', qualifier: 'action' },
          { kind: 'def', name: 'invSmall', qualifier: 'val' },
        ],
    }],
    };
    const invariantName = 'invSmall';
    const fixedMessage = `❌ ${invariantName}\nerror: Invariant violated`;
    const tracePrefix = 'An example execution:\n[State 0] { counter: 0 }\n';
    const traceLength = bodyLength - fixedMessage.length - 1;
    const trace = `${tracePrefix}${'x'.repeat(traceLength - tracePrefix.length)}`;
    const retainedTraceBudget = 8_000 - fixedMessage.length - 1 - '\n[output truncated]'.length;
    const expectedTrace = bodyLength === 8_000 ? trace : trace.slice(0, retainedTraceBudget);
    const expectedSuffix = bodyLength === 8_000 ? '' : '\n[output truncated]';
    processResponses.push(
      { code: 0 },
      { code: 0 },
      {
        code: 1,
        stderr: 'error: Invariant violated\n',
        stdout: trace,
      },
    );

    try {
      const result = await runFormalSpecVerification('```quint\nmodule verify {}\n```', directory, { modelCheckTimeoutSeconds: 300 });
      const message = result.quint.run?.message ?? '';

      expect(result.quint.run?.status).toBe('failed');
      expect(message).toBe(`${fixedMessage}\n${expectedTrace}${expectedSuffix}`);
      expect(message).toContain('An example execution:');
      expect(message).toContain('[State 0] { counter: 0 }');
      expect(message).toContain('error: Invariant violated');
      expect(message).toHaveLength(8_000);
      expect(message.startsWith(fixedMessage)).toBe(true);
      expect(expectedTrace).toBe(bodyLength === 8_000 ? trace : trace.slice(0, retainedTraceBudget));
      expect(message.endsWith(bodyLength === 8_000 ? 'x' : '[output truncated]')).toBe(true);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('should treat a run workspace creation failure as a started verification error', async () => {
    const directory = createTestDirectory();
    writeFileSync(join(directory, '.takt'), 'not a directory');

    try {
      const result = await runFormalSpecVerification('```quint\nmodule verify {}\n```', directory, { modelCheckTimeoutSeconds: 300 });

      expect(result).toMatchObject({
        verdict: 'error',
        verificationStarted: true,
        quint: { status: 'error' },
        alloy: { status: 'skipped' },
      });
      expect(mockSpawnManagedProcess).not.toHaveBeenCalled();
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('should remove a partially created run workspace when specs creation fails', async () => {
    const directory = createTestDirectory();
    failSpecsDirectoryCreation.enabled = true;

    try {
      const result = await runFormalSpecVerification('```quint\nmodule verify {}\n```', directory, { modelCheckTimeoutSeconds: 300 });

      expect(result).toMatchObject({
        verdict: 'error',
        verificationStarted: true,
        quint: { status: 'error', message: 'specs directory creation failed' },
        alloy: { status: 'skipped' },
      });
      expect(readdirSync(join(directory, '.takt', 'runs'))
        .filter((name) => name.startsWith('verify-'))).toEqual([]);
    } finally {
      failSpecsDirectoryCreation.enabled = false;
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('should remove a workspace after a synchronous spawn failure with no child returned', async () => {
    const directory = createTestDirectory();
    processBoundaryControls.throwOnSpawn = true;

    try {
      const result = await runFormalSpecVerification(validAlloyResponse(), directory, { modelCheckTimeoutSeconds: 300 });

      expect(result).toMatchObject({ verdict: 'error', verificationStarted: true });
      expect(mockSpawnManagedProcess).toHaveBeenCalledOnce();
      expect(readdirSync(join(directory, '.takt', 'runs'))
        .filter((name) => name.startsWith('verify-'))).toEqual([]);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('should remove stale abandoned verify workspaces while retaining recent and unrelated entries', async () => {
    const directory = createTestDirectory();
    const runsDirectory = join(directory, '.takt', 'runs');
    const staleDirectory = join(runsDirectory, 'verify-stale');
    const recentDirectory = join(runsDirectory, 'verify-recent');
    const unrelatedDirectory = join(runsDirectory, 'unrelated');
    mkdirSync(staleDirectory, { recursive: true, mode: 0o700 });
    mkdirSync(recentDirectory, { recursive: true, mode: 0o700 });
    mkdirSync(unrelatedDirectory, { recursive: true, mode: 0o700 });
    const staleTime = new Date(Date.now() - 2 * 60 * 60 * 1000);
    utimesSync(staleDirectory, staleTime, staleTime);

    try {
      await runFormalSpecVerification('No formal specification was generated.', directory, { modelCheckTimeoutSeconds: 300 });

      expect(existsSync(staleDirectory)).toBe(false);
      expect(existsSync(recentDirectory)).toBe(true);
      expect(existsSync(unrelatedDirectory)).toBe(true);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('should retain an active workspace when sequential Alloy checks outlive the stale threshold', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    const directory = createTestDirectory();
    installConfiguredAlloyJar(directory);
    const checkNumbers = Array.from({ length: 80 }, (_, index) => index);
    const retainedSpecifications: boolean[] = [];
    processResponses.push(
      { code: 0, stderr: 'openjdk version "17.0.1"' },
      { code: 0, stdout: checkNumbers.map((index) => `${index} . Check Safety${index} for 1`).join('\n') },
      ...checkNumbers.map(() => ({
        code: 0,
        beforeExit: async () => {
          const activeWorkspace = spawnedProcesses.at(-1)?.options.cwd;
          if (activeWorkspace === undefined) {
            throw new Error('Alloy process has no workspace');
          }
          vi.setSystemTime(Date.now() + 50_000);
          await runFormalSpecVerification('No formal specification was generated.', directory, { modelCheckTimeoutSeconds: 300 });
          retainedSpecifications.push(existsSync(join(activeWorkspace, 'specs', 'spec.als')));
        },
      })),
    );

    try {
      const result = await runFormalSpecVerification(validAlloyResponse(), directory, { modelCheckTimeoutSeconds: 300 });

      expect(result.alloy).toMatchObject({ status: 'passed', checks: checkNumbers });
      expect(retainedSpecifications).toEqual(checkNumbers.map(() => true));
      expect(readdirSync(join(directory, '.takt', 'runs'))).toEqual([]);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('should preserve the verification result when run cleanup fails', async () => {
    const directory = createTestDirectory();
    installConfiguredAlloyJar(directory);
    processResponses.push(
      { code: 0, stderr: 'openjdk version "17.0.1"' },
      { code: 0, stdout: '0 . Check Safety for 1\n' },
      { code: 1, stderr: 'counterexample' },
    );
    failVerifyRunRemoval.enabled = true;

    try {
      const result = await runFormalSpecVerification(validAlloyResponse(), directory, { modelCheckTimeoutSeconds: 300 });

      expect(result.verdict).toBe('failed');
      expect(result.alloy).toMatchObject({ status: 'failed', message: 'counterexample' });
      expect(readdirSync(join(directory, '.takt', 'runs'))
        .filter((name) => name.startsWith('verify-'))).toHaveLength(1);
    } finally {
      failVerifyRunRemoval.enabled = false;
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('should classify a normal verification exit as failed and a process error as error', async () => {
    const directory = createTestDirectory();
    const quintResponse = '```quint\nmodule verify {}\n```';
    try {
      processResponses.push(
        { code: 0 },
        { code: 0 },
        { code: 0, stderr: 'error: Invariant violated' },
      );
      const passed = await runFormalSpecVerification(quintResponse, directory, { modelCheckTimeoutSeconds: 300 });
      expect(passed.quint.run).toEqual({ status: 'passed' });

      processResponses.push(
        { code: 0 },
        { code: 0 },
        { code: 1, stderr: 'counterexample' },
      );
      const failed = await runFormalSpecVerification(quintResponse, directory, { modelCheckTimeoutSeconds: 300 });
      expect(failed.verdict).toBe('failed');
      expect(failed.quint.run).toMatchObject({ status: 'failed', message: 'counterexample' });

      processResponses.push(
        { code: 0 },
        { code: 0 },
        { error: new Error('error: Invariant violated') },
      );
      const errored = await runFormalSpecVerification(quintResponse, directory, { modelCheckTimeoutSeconds: 300 });
      expect(errored.verdict).toBe('error');
      expect(errored.quint.run).toMatchObject({ status: 'error', message: 'error: Invariant violated' });
      expect(errored.quint.run?.message).not.toContain('invSafe');

      processResponses.push(
        { code: 0 },
        { code: 0 },
        { code: null, stderr: 'error: Invariant violated' },
      );
      const statusless = await runFormalSpecVerification(quintResponse, directory, { modelCheckTimeoutSeconds: 300 });
      expect(statusless.verdict).toBe('error');
      expect(statusless.quint.run).toMatchObject({ status: 'error' });
      expect(statusless.quint.run?.message).not.toContain('invSafe');

      processResponses.push(
        { code: 0 },
        { code: 0 },
        { code: null, signal: 'SIGTERM', stderr: 'error: Invariant violated' },
      );
      const signaled = await runFormalSpecVerification(quintResponse, directory, { modelCheckTimeoutSeconds: 300 });
      expect(signaled.quint.run).toMatchObject({ status: 'error' });
      expect(signaled.quint.run?.message).not.toContain('invSafe');
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('should classify a process timeout as error', async () => {
    vi.useFakeTimers();
    const directory = createTestDirectory();
    processResponses.push(
      { code: 0 },
      { code: 0 },
      { hang: true, stderr: 'error: Invariant violated' },
    );
    try {
      const verification = runFormalSpecVerification('```quint\nmodule verify {}\n```', directory, { modelCheckTimeoutSeconds: 300 });
      await vi.advanceTimersByTimeAsync(60_000);
      const result = await verification;

      expect(result.verdict).toBe('error');
      expect(result.quint.run).toMatchObject({ status: 'error' });
      expect(result.quint.run?.message).toContain('timed out');
      expect(result.quint.run?.message).not.toContain('invSafe');
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('should pass every parsed Quint target to verification and select the temporal backend', async () => {
    const directory = createTestDirectory();
    parseResult = {
      modules: [{
        name: 'workflowModel',
        declarations: [
          { kind: 'def', name: 'init', qualifier: 'action' },
          { kind: 'def', name: 'step', qualifier: 'action' },
          { kind: 'def', name: 'invSafe', qualifier: 'val' },
          { kind: 'def', name: 'invConsistent', qualifier: 'val' },
          { kind: 'def', name: 'propEventually', qualifier: 'temporal' },
        ],
      }],
    };
    processResponses.push(
      { code: 0 },
      { code: 0 },
      { code: 0 },
      { code: 0, stderr: 'openjdk version "17.0.1"' },
      { code: 0 },
    );
    try {
      const result = await runFormalSpecVerification('```quint\nmodule verify {}\n```', directory, { modelCheckTimeoutSeconds: 300 });
      const quintCalls = spawnedProcesses.filter(({ command }) => command === process.execPath);
      const [parseCall, typecheckCall, runCall, verifyCall] = quintCalls;
      const specificationPath = parseCall?.args[2];

      expect(result.verdict).toBe('passed');
      expect(result.quint.invariants).toEqual(['invSafe', 'invConsistent']);
      expect(result.quint.temporal).toEqual(['propEventually']);
      expect(specificationPath).toEqual(expect.any(String));
      expect(spawnedProcesses.map(({ command, args }) => command === 'java' ? 'java' : args[1]))
        .toEqual(['parse', 'typecheck', 'run', 'java', 'verify']);
      expect(typecheckCall?.args.slice(1)).toEqual(['typecheck', specificationPath]);
      expect(runCall?.args.slice(1)).toEqual([
        'run', specificationPath,
        '--main', 'workflowModel',
        '--backend', 'typescript',
        '--max-samples', '1',
        '--max-steps', '20',
        '--verbosity', '2',
        '--invariants', 'invSafe', 'invConsistent',
      ]);
      expect(verifyCall?.args.slice(1)).toEqual([
        'verify', specificationPath,
        '--main', 'workflowModel',
        '--backend', 'tlc',
        '--max-steps', '20',
        '--invariant', 'invSafe,invConsistent',
        '--temporal', 'propEventually',
      ]);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('should extract TLC stdout diagnostics without including the stderr summary or startup logs', async () => {
    const directory = createTestDirectory();
    const diagnostics = [
      'Error: TLC threw an unexpected exception.',
      'This was probably caused by an error in the spec or model.',
      'The exception was a java.lang.RuntimeException',
      ': TLC encountered a non-enumerable quantifier bound',
      'Int.',
      'Error: The behavior up to this point is:',
      'State 1: <Initial predicate>',
      '/\\ rejected = FALSE',
      '[failure] TLC encountered an error (592ms).',
    ].join('\n');
    mockTlcVerification({
      code: 1,
      stderr: 'error: TLC error (see output above)',
      stdout: [
        'Parsing file /tmp/spec.tla',
        'Semantic processing of module verify',
        'SANY parser log',
        'WARNING: protobuf warning',
        '[0.123s][warning][gc] GC warning',
        'fingerprint statistics: 100 states',
        diagnostics,
      ].join('\n'),
    });

    try {
      const result = await runFormalSpecVerification('```quint\nmodule verify {}\n```', directory, { modelCheckTimeoutSeconds: 300 });

      expect(result.quint.verify).toEqual({ status: 'failed', message: diagnostics });
      expect(result.message).toBe(diagnostics);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it.each(['\n', '\r\n'])('should retain diagnostic words and trace values with line ending %j', async (newline) => {
    const directory = createTestDirectory();
    const diagnosticLines = [
      'Error: TLC could not compute a fingerprint.',
      'Error: The behavior up to this point is:',
      'State 1: <Initial predicate>',
      '/\\ phase = "GC"',
      '/\\ source = "SANY"',
      '/\\ format = "protobuf"',
      '/\\ fingerprint = 1',
      '[failure] TLC encountered an error (592ms).',
    ];
    mockTlcVerification({
      code: 1,
      stdout: diagnosticLines.join(newline),
      stderr: 'error: TLC error (see output above)',
    });

    try {
      const result = await runFormalSpecVerification('```quint\nmodule verify {}\n```', directory, { modelCheckTimeoutSeconds: 300 });

      expect(result.quint.verify).toEqual({ status: 'failed', message: diagnosticLines.join('\n') });
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it.each([
    { stdout: 'unclassified TLC output', stderr: 'error: TLC error (see output above)' },
    { stdout: 'error: unknown failure\nParsing file /tmp/spec.tla', stderr: 'unknown stderr detail' },
    { stdout: 'unclassified TLC output', stderr: 'Error: stderr failure\n[failure] stderr summary' },
  ])('should retain both raw streams when stdout has no TLC diagnostic marker: %j', async (output) => {
    const directory = createTestDirectory();
    mockTlcVerification({ code: 1, ...output });

    try {
      const result = await runFormalSpecVerification('```quint\nmodule verify {}\n```', directory, { modelCheckTimeoutSeconds: 300 });

      expect(result.quint.verify).toEqual({ status: 'failed', message: `${output.stderr}\n${output.stdout}` });
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('should retain both raw streams when a failure summary has no Error block', async () => {
    const directory = createTestDirectory();
    const summary = '[failure] TLC encountered an error (592ms).';
    const output = {
      stdout: `Parsing file /tmp/spec.tla\n${summary}`,
      stderr: 'error: TLC error (see output above)',
    };
    mockTlcVerification({ code: 1, ...output });

    try {
      const result = await runFormalSpecVerification('```quint\nmodule verify {}\n```', directory, { modelCheckTimeoutSeconds: 300 });

      expect(result.quint.verify).toEqual({ status: 'failed', message: `${output.stderr}\n${output.stdout}` });
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('should retain the Java spawn failure from stderr alongside the stdout failure summary', async () => {
    const directory = createTestDirectory();
    const output = {
      stdout: '[failure] TLC encountered an error (592ms).',
      stderr: 'error: Failed to spawn TLC: spawn java EAGAIN',
    };
    mockTlcVerification({ code: 1, ...output });

    try {
      const result = await runFormalSpecVerification('```quint\nmodule verify {}\n```', directory, { modelCheckTimeoutSeconds: 300 });

      expect(result.quint.verify).toEqual({ status: 'failed', message: `${output.stderr}\n${output.stdout}` });
      expect(result.message).toBe(result.quint.verify?.message);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it.each([0, 8_001, 1024 * 1024 + 1])('should retain TLC timeout guidance with %i output characters', async (outputLength) => {
    vi.useFakeTimers();
    const directory = createTestDirectory();
    mockTlcVerification({ hang: true, stdout: 'x'.repeat(outputLength) });

    try {
      const verification = runFormalSpecVerification('```quint\nmodule verify {}\n```', directory, { modelCheckTimeoutSeconds: 300 });
      await vi.advanceTimersByTimeAsync(300_000);
      const result = await verification;

      expect(result.verdict).toBe('error');
      expect(result.quint.verify).toMatchObject({ status: 'error' });
      expect(result.quint.verify?.message).toMatch(/^TLC exhaustively/);
      expect(result.quint.verify?.message).toContain('Process timed out after 300000 ms');
      expect(result.quint.verify?.message).toContain('entire state space');
      expect(result.quint.verify?.message).toContain('--max-steps does not limit TLC');
      expect(result.quint.verify?.message).toContain('Bound all state variables');
      expect(result.quint.verify?.message).toContain('finite ranges');
      if (outputLength > 8_000) {
        expect(result.quint.verify?.message).toHaveLength(8_000);
        expect(result.quint.verify?.message).toContain('[output truncated]');
      }
      if (outputLength > 1024 * 1024) {
        expect(result.quint.verify?.message).toContain('capture limit');
        expect(result.quint.verify?.message).toContain('diagnostics may be missing');
      } else {
        expect(result.quint.verify?.message).not.toContain('capture limit');
      }
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it.each(['stdout', 'stderr'] as const)('should warn when TLC %s exceeds the capture limit', async (stream) => {
    const directory = createTestDirectory();
    mockTlcVerification({
      code: 1,
      stdout: 'Error: TLC encountered a non-enumerable quantifier bound\nInt.',
      stderr: 'error: TLC error (see output above)',
      [stream]: `${'x'.repeat(1024 * 1024)}\nError: diagnostic beyond capture limit`,
    });

    try {
      const result = await runFormalSpecVerification('```quint\nmodule verify {}\n```', directory, { modelCheckTimeoutSeconds: 300 });

      expect(result.quint.verify).toMatchObject({ status: 'failed' });
      expect(result.quint.verify?.message).toMatch(/^TLC output[^\n]*capture limit[^\n]*diagnostics may be missing/);
      expect(result.quint.verify?.message).not.toContain('diagnostic beyond capture limit');
      expect(result.message).toBe(result.quint.verify?.message);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('should apply a configured timeout to Quint model checking while keeping TLC guidance', async () => {
    vi.useFakeTimers();
    const directory = createTestDirectory();
    mockTlcVerification({ hang: true });

    try {
      const verification = runFormalSpecVerification('```quint\nmodule verify {}\n```', directory, {
        modelCheckTimeoutSeconds: 2,
      });
      await vi.advanceTimersByTimeAsync(2_000);
      const result = await verification;

      expect(result.quint.verify?.message).toContain('Process timed out after 2000 ms');
      expect(result.quint.verify?.message).toMatch(/^TLC exhaustively/);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('should keep Quint parse, typecheck, and run at 60 seconds when model-check timeout is customized', async () => {
    vi.useFakeTimers();
    const directory = createTestDirectory();
    processResponses.push(
      { code: 0 },
      { code: 0 },
      { hang: true },
    );
    let settled = false;

    try {
      const verification = runFormalSpecVerification('```quint\nmodule verify {}\n```', directory, {
        modelCheckTimeoutSeconds: 2,
      });
      void verification.then(() => {
        settled = true;
      });
      await vi.advanceTimersByTimeAsync(2_000);
      expect(settled).toBe(false);
      await vi.advanceTimersByTimeAsync(58_000);
      const result = await verification;
      expect(result.quint.run?.message).toContain('Process timed out after 60000 ms');
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('should apply the configured timeout to Alloy command enumeration', async () => {
    vi.useFakeTimers();
    const directory = createTestDirectory();
    installConfiguredAlloyJar(directory);
    processResponses.push(
      { code: 0, stderr: 'openjdk version "17.0.1"' },
      { hang: true },
    );

    try {
      const verification = runFormalSpecVerification(validAlloyResponse(), directory, {
        modelCheckTimeoutSeconds: 3,
      });
      await vi.advanceTimersByTimeAsync(3_000);
      const result = await verification;

      expect(result.alloy).toMatchObject({
        status: 'error',
        message: expect.stringContaining('Process timed out after 3000 ms'),
      });
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('should apply the configured timeout to each Alloy check execution', async () => {
    vi.useFakeTimers();
    const directory = createTestDirectory();
    installConfiguredAlloyJar(directory);
    processResponses.push(
      { code: 0, stderr: 'openjdk version "17.0.1"' },
      { code: 0, stdout: '0 . Check Safety for 1\n' },
      { hang: true },
    );

    try {
      const verification = runFormalSpecVerification(validAlloyResponse(), directory, {
        modelCheckTimeoutSeconds: 4,
      });
      await vi.advanceTimersByTimeAsync(4_000);
      const result = await verification;

      expect(result.alloy).toMatchObject({
        status: 'error',
        message: expect.stringContaining('Process timed out after 4000 ms'),
      });
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('should use the configured timeout for Alloy jar downloads', async () => {
    vi.useFakeTimers();
    const directory = createTestDirectory();
    let downloadSignal: AbortSignal | undefined;
    const fetchMock = vi.fn((_url: string | URL | Request, init?: RequestInit) => new Promise<Response>((_resolve, reject) => {
      downloadSignal = init?.signal ?? undefined;
      init?.signal?.addEventListener('abort', () => reject(init.signal?.reason), { once: true });
    }));
    vi.stubGlobal('fetch', fetchMock);
    processResponses.push({ code: 0, stderr: 'openjdk version "17.0.1"' });

    try {
      const verification = runFormalSpecVerification(validAlloyResponse(), directory, {
        modelCheckTimeoutSeconds: 5,
      });
      await vi.advanceTimersByTimeAsync(5_000);
      const result = await verification;

      expect(fetchMock).toHaveBeenCalledOnce();
      expect(downloadSignal?.aborted).toBe(true);
      expect(result.alloy.status).toBe('error');
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('should fail explicitly when no parsed module has both executable actions', async () => {
    const directory = createTestDirectory();
    parseResult = {
      modules: [{
        name: 'helper',
        declarations: [{ kind: 'def', name: 'constant', qualifier: 'val' }],
      }],
    };
    processResponses.push(
      { code: 0 },
      { code: 0 },
      { code: 0, stderr: 'openjdk version "17.0.1"' },
    );

    try {
      const result = await runFormalSpecVerification('```quint\nmodule helper {}\n```', directory, { modelCheckTimeoutSeconds: 300 });

      expect(result.verdict).toBe('error');
      expect(result.quint.run).toMatchObject({
        status: 'error',
        message: 'Quint verification requires a module with action init and action step.',
      });
      expect(spawnedProcesses.some(({ args }) => args.includes('run'))).toBe(false);
      expect(spawnedProcesses.some(({ args }) => args.includes('verify'))).toBe(false);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('should not invoke Java discovery when Quint verification cannot run and Alloy is absent', async () => {
    const directory = createTestDirectory();
    processResponses.push({ code: 1, stderr: 'Quint parse failed' });

    try {
      const result = await runFormalSpecVerification('```quint\nmodule invalid {}\n```', directory, { modelCheckTimeoutSeconds: 300 });

      expect(result.quint.verify).toMatchObject({
        status: 'skipped',
        message: 'Quint verification was skipped because an earlier Quint stage did not pass.',
      });
      expect(spawnedProcesses).toHaveLength(1);
      expect(spawnedProcesses.some(({ command }) => command === 'java')).toBe(false);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('should collect Alloy results after an independent Quint parse error and clean the run directory', async () => {
    const directory = createTestDirectory();
    installConfiguredAlloyJar(directory);
    processResponses.push(
      { code: 1, stderr: 'Quint parse failed' },
      { code: 0, stderr: 'openjdk version "17.0.1"' },
      { code: 0, stdout: '0 . Check Safety for 3\n1 . Run Report for 3\n' },
      { code: 0 },
    );
    try {
      const result = await runFormalSpecVerification(
        ['```quint', 'module invalid {', '```', validAlloyResponse()].join('\n'),
        directory,
        { modelCheckTimeoutSeconds: 300 },
      );

      expect(result.verdict).toBe('error');
      expect(result.quint.parse).toMatchObject({ status: 'error', message: 'Quint parse failed' });
      expect(result.alloy).toMatchObject({ status: 'passed', checks: [0] });
      expect(result.alloy.commands).toEqual([
        { number: 0, type: 'check', label: 'Safety' },
        { number: 1, type: 'run', label: 'Report' },
      ]);
      expect(spawnedProcesses.every(({ options }) => options.cwd?.includes('/.takt/runs/verify-'))).toBe(true);
      expect(spawnedProcesses.every(({ options }) => options.env?.TMPDIR === options.cwd)).toBe(true);
      const runParent = join(directory, '.takt', 'runs');
      expect(readdirSync(runParent).filter((name) => name.startsWith('verify-'))).toEqual([]);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('should not report an Alloy-only specification as passed when every stage is skipped', async () => {
    const directory = createTestDirectory();
    installConfiguredAlloyJar(directory);
    processResponses.push({ error: new Error('java is unavailable') });
    try {
      const result = await runFormalSpecVerification(validAlloyResponse(), directory, { modelCheckTimeoutSeconds: 300 });

      expect(result.verdict).toBe('error');
      expect(result.quint.status).toBe('skipped');
      expect(result.alloy.status).toBe('skipped');
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('should classify an Alloy counterexample as failed and an Alloy process error as error', async () => {
    const directory = createTestDirectory();
    installConfiguredAlloyJar(directory);
    try {
      processResponses.push(
        { code: 0, stderr: 'openjdk version "17.0.1"' },
        { code: 0, stdout: '0 . Check Safety for 3\n' },
        { code: 0, stdout: 'counterexample' },
      );
      const failed = await runFormalSpecVerification(validAlloyResponse(), directory, { modelCheckTimeoutSeconds: 300 });
      expect(failed.verdict).toBe('failed');
      expect(failed.alloy).toMatchObject({ status: 'failed', message: 'counterexample' });

      processResponses.push(
        { code: 0, stderr: 'openjdk version "17.0.1"' },
        { code: 0, stdout: '0 . Check Safety for 3\n' },
        { error: new Error('Alloy process unavailable') },
      );
      const errored = await runFormalSpecVerification(validAlloyResponse(), directory, { modelCheckTimeoutSeconds: 300 });
      expect(errored.verdict).toBe('error');
      expect(errored.alloy).toMatchObject({ status: 'error', message: 'Alloy process unavailable' });

      processResponses.push(
        { code: 0, stderr: 'openjdk version "17.0.1"' },
        { code: 0, stdout: '0 . Check Safety for 3\n' },
        { code: null },
      );
      const statusless = await runFormalSpecVerification(validAlloyResponse(), directory, { modelCheckTimeoutSeconds: 300 });
      expect(statusless.verdict).toBe('error');
      expect(statusless.alloy).toMatchObject({ status: 'error' });
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('should report a configured Alloy jar preparation failure as error', async () => {
    const directory = createTestDirectory();
    const previousJarPath = process.env.TAKT_ALLOY_JAR;
    process.env.TAKT_ALLOY_JAR = join(directory, 'missing-alloy.jar');
    processResponses.push({ code: 0, stderr: 'openjdk version "17.0.1"' });
    try {
      const result = await runFormalSpecVerification(validAlloyResponse(), directory, { modelCheckTimeoutSeconds: 300 });

      expect(result.verdict).toBe('error');
      expect(result.alloy).toMatchObject({ status: 'error' });
      expect(result.alloy.message).toContain('Configured Alloy jar is not a readable file');
      expect(spawnedProcesses).toHaveLength(1);
    } finally {
      if (previousJarPath === undefined) {
        delete process.env.TAKT_ALLOY_JAR;
      } else {
        process.env.TAKT_ALLOY_JAR = previousJarPath;
      }
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('should resolve a relative configured Alloy jar from the project cwd', async () => {
    const directory = createTestDirectory();
    const fixtureDirectory = join(directory, 'fixtures');
    mkdirSync(fixtureDirectory, { recursive: true, mode: 0o700 });
    const jarPath = join(fixtureDirectory, 'alloy.jar');
    writeFileSync(jarPath, Buffer.from([0x50, 0x4b, 0x03, 0x04]), { mode: 0o600 });
    process.env.TAKT_ALLOY_JAR = 'fixtures/alloy.jar';
    processResponses.push(
      { code: 0, stderr: 'openjdk version "17.0.1"' },
      { code: 0, stdout: '0 . Check Safety for 1\n' },
      { code: 0 },
    );

    try {
      const result = await runFormalSpecVerification(validAlloyResponse(), directory, { modelCheckTimeoutSeconds: 300 });

      expect(result.alloy.status).toBe('passed');
      const alloyCalls = spawnedProcesses.filter(({ command }) => command === 'java');
      expect(alloyCalls.at(-1)?.args[1]).toBe(jarPath);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('should download the Alloy jar into the isolated cache without using a real fetch', async () => {
    const directory = createTestDirectory();
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      arrayBuffer: async () => Buffer.from([0x50, 0x4b, 0x03, 0x04]),
    } as unknown as Response);
    vi.stubGlobal('fetch', fetchMock);
    alloyJarDigestOverride.value = EXPECTED_ALLOY_JAR_SHA256;
    processResponses.push(
      { code: 0, stderr: 'openjdk version "17.0.1"' },
      { code: 0, stdout: '0 . Check Safety for 1\n' },
      { code: 0 },
    );

    try {
      const result = await runFormalSpecVerification(validAlloyResponse(), directory, { modelCheckTimeoutSeconds: 300 });
      const cacheDirectory = join(directory, '.takt', 'cache', 'alloy', '6.2.0');

      expect(result.alloy.status).toBe('passed');
      expect(fetchMock).toHaveBeenCalledOnce();
      expect(existsSync(join(cacheDirectory, 'alloy.jar'))).toBe(true);
      expect(readdirSync(cacheDirectory).filter((name) => name.startsWith('.alloy-'))).toEqual([]);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('should report an Alloy jar HTTP failure without leaving a temporary archive', async () => {
    const directory = createTestDirectory();
    const fetchMock = vi.fn().mockResolvedValue({ ok: false, status: 503 } as unknown as Response);
    vi.stubGlobal('fetch', fetchMock);
    processResponses.push({ code: 0, stderr: 'openjdk version "17.0.1"' });

    try {
      const result = await runFormalSpecVerification(validAlloyResponse(), directory, { modelCheckTimeoutSeconds: 300 });
      const cacheDirectory = join(directory, '.takt', 'cache', 'alloy', '6.2.0');

      expect(result.alloy).toMatchObject({
        status: 'error',
        message: 'Alloy Analyzer could not be prepared: Alloy jar download failed with HTTP status 503',
      });
      expect(fetchMock).toHaveBeenCalledOnce();
      expect(readdirSync(cacheDirectory).filter((name) => name.startsWith('.alloy-'))).toEqual([]);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('should reject a downloaded Alloy jar whose SHA-256 does not match the pinned artifact', async () => {
    const directory = createTestDirectory();
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      arrayBuffer: async () => Buffer.from([0x50, 0x4b, 0x03, 0x04]),
    } as unknown as Response);
    vi.stubGlobal('fetch', fetchMock);
    processResponses.push({ code: 0, stderr: 'openjdk version "17.0.1"' });

    try {
      const result = await runFormalSpecVerification(validAlloyResponse(), directory, { modelCheckTimeoutSeconds: 300 });
      const cacheDirectory = join(directory, '.takt', 'cache', 'alloy', '6.2.0');

      expect(result.alloy).toMatchObject({
        status: 'error',
        message: expect.stringContaining('Alloy jar SHA-256 mismatch'),
      });
      expect(fetchMock).toHaveBeenCalledOnce();
      expect(existsSync(join(cacheDirectory, 'alloy.jar'))).toBe(false);
      expect(readdirSync(cacheDirectory).filter((name) => name.startsWith('.alloy-'))).toEqual([]);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('should reject a cached Alloy jar whose SHA-256 does not match the pinned artifact', async () => {
    const directory = createTestDirectory();
    const cacheDirectory = join(directory, '.takt', 'cache', 'alloy', '6.2.0');
    mkdirSync(cacheDirectory, { recursive: true, mode: 0o700 });
    writeFileSync(join(cacheDirectory, 'alloy.jar'), Buffer.from([0x50, 0x4b, 0x03, 0x04]), { mode: 0o600 });
    processResponses.push({ code: 0, stderr: 'openjdk version "17.0.1"' });

    try {
      const result = await runFormalSpecVerification(validAlloyResponse(), directory, { modelCheckTimeoutSeconds: 300 });

      expect(result.alloy).toMatchObject({
        status: 'error',
        message: expect.stringContaining('Alloy jar SHA-256 mismatch'),
      });
      expect(spawnedProcesses).toHaveLength(1);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('should reject truncated Alloy command enumeration output before executing any check', async () => {
    const directory = createTestDirectory();
    installConfiguredAlloyJar(directory);
    const oversizedCommands = `0 . Check First\n${'not-a-command\n'.repeat(100_000)}1 . Check Later\n`;
    processResponses.push(
      { code: 0, stderr: 'openjdk version "17.0.1"' },
      { code: 0, stdout: oversizedCommands },
    );

    try {
      const result = await runFormalSpecVerification(validAlloyResponse(), directory, { modelCheckTimeoutSeconds: 300 });

      expect(result.alloy).toMatchObject({
        status: 'error',
        message: 'Alloy command enumeration output was truncated before all commands could be read.',
      });
      expect(spawnedProcesses).toHaveLength(2);
      expect(spawnedProcesses.some(({ args }) => args.includes('exec'))).toBe(false);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('should reject an invalid Alloy jar archive without leaving a temporary archive', async () => {
    const directory = createTestDirectory();
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      arrayBuffer: async () => Buffer.from('not a jar'),
    } as unknown as Response);
    vi.stubGlobal('fetch', fetchMock);
    processResponses.push({ code: 0, stderr: 'openjdk version "17.0.1"' });

    try {
      const result = await runFormalSpecVerification(validAlloyResponse(), directory, { modelCheckTimeoutSeconds: 300 });
      const cacheDirectory = join(directory, '.takt', 'cache', 'alloy', '6.2.0');

      expect(result.alloy).toMatchObject({
        status: 'error',
        message: 'Alloy Analyzer could not be prepared: Alloy jar download did not return a valid archive',
      });
      expect(fetchMock).toHaveBeenCalledOnce();
      expect(readdirSync(cacheDirectory).filter((name) => name.startsWith('.alloy-'))).toEqual([]);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
});

describe('extractFormalSpecBlocks', () => {
  it('should return closed quint and alloy blocks in response order without using older or unrelated text', () => {
    const response = [
      'Earlier context contained ```quint, but it is not part of this response.',
      '````text',
      '```quint',
      'This nested-looking line is text, not a Quint block.',
      '````',
      '```quint',
      'module first {}',
      '```',
      '~~~quint',
      'module second {}',
      '~~~',
      '> ```alloy',
      'check QuotedText',
      '> ```',
      '```alloy',
      'check CurrentAgreement',
      '```',
    ].join('\n');

    expect(extractFormalSpecBlocks(response)).toEqual({
      quint: ['module first {}', 'module second {}'],
      alloy: ['check CurrentAgreement'],
    });
  });

  it('should return empty block lists when the response contains no target block', () => {
    expect(extractFormalSpecBlocks('inline ` ```quint module fake {} ``` `\n```text\nplain text\n```')).toEqual({
      quint: [],
      alloy: [],
    });
  });

  it('should reject an unclosed target block instead of returning a partial specification', () => {
    expect(() => extractFormalSpecBlocks('```quint\nmodule incomplete {}')).toThrow(/fence|closed|block/i);
  });
});

describe('detectJavaMajorVersion', () => {
  it.each([
    ['openjdk version "17.0.12" 2024-07-16', 17],
    ['openjdk version "21.0.4" 2024-07-16 LTS', 21],
    ['java version "1.8.0_402"', 8],
    ['openjdk 16.0.2 2021-07-20', 16],
  ])('should parse the Java major version from %s', (output, expected) => {
    expect(detectJavaMajorVersion(output)).toBe(expected);
  });

  it.each(['', 'java: command not found', 'version unavailable'])('should return undefined for unparseable Java output: %s', (output) => {
    expect(detectJavaMajorVersion(output)).toBeUndefined();
  });
});

describe('selectQuintVerificationTargets', () => {
  it('should select every inv value and prop temporal definition while ignoring other definitions', () => {
    const parseResult = {
      modules: [{
        name: 'workflowModel',
        declarations: [
          { kind: 'def', name: 'invSafe', qualifier: 'val' },
          { kind: 'def', name: 'invOwner', qualifier: 'val' },
          { kind: 'def', name: 'propEventuallyDone', qualifier: 'temporal' },
          { kind: 'def', name: 'notAnInvariant', qualifier: 'val' },
          { kind: 'def', name: 'step', qualifier: 'action' },
        ],
      }],
    };

    expect(selectQuintVerificationTargets(parseResult)).toEqual({
      invariants: [
        { moduleName: 'workflowModel', name: 'invSafe' },
        { moduleName: 'workflowModel', name: 'invOwner' },
      ],
      temporal: [{ moduleName: 'workflowModel', name: 'propEventuallyDone' }],
    });
  });

  it('should not turn names from comments or string-like entries into verification targets', () => {
    const parseResult = {
      modules: [{
        name: 'workflowModel',
        declarations: [
          { kind: 'comment', name: 'invFake' },
          { kind: 'string', name: 'propFake' },
          { kind: 'def', name: 'invReal', qualifier: 'val' },
        ],
      }],
    };

    expect(selectQuintVerificationTargets(parseResult)).toEqual({
      invariants: [{ moduleName: 'workflowModel', name: 'invReal' }],
      temporal: [],
    });
  });
});

describe('selectAlloyCheckTargets', () => {
  it('should return every parsed check number, preserve duplicates by number, and exclude run commands', () => {
    expect(selectAlloyCheckTargets([
      { number: 0, type: 'check', label: 'ModeGate' },
      { number: 1, type: 'run', label: 'ReachReport' },
      { number: 2, type: 'check', label: 'NoRetry' },
      { number: 3, type: 'check', label: 'ModeGate' },
    ])).toEqual([0, 2, 3]);
  });
});
