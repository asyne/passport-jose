import { expect, vi } from 'vitest';

// Custom Passport strategy matchers for Vitest
interface CustomMatchers<R = unknown> {
  toAuthenticate(): R;
  toFail(challenge?: string, status?: number): R;
  toRedirect(url?: string): R;
  toPass(): R;
  toError(error?: Error): R;
}

declare module 'vitest' {
  interface Assertion<T = any> extends CustomMatchers<T> {}
  interface AsymmetricMatchersContaining extends CustomMatchers {}
}

// Mock implementation of passport strategy testing
interface StrategyResult {
  success?: { user: any; info?: any };
  fail?: { challenge?: string; status?: number };
  redirect?: { url: string };
  pass?: {};
  error?: { error: Error };
}

// Helper to test passport strategies
export function testStrategy(strategy: any, request: any): Promise<StrategyResult> {
  return new Promise((resolve) => {
    const result: StrategyResult = {};

    // Mock the strategy methods
    strategy.success = vi.fn((user: any, info?: any) => {
      result.success = { user, info };
      resolve(result);
    });

    strategy.fail = vi.fn((challenge?: string, status?: number) => {
      result.fail = { challenge, status };
      resolve(result);
    });

    strategy.redirect = vi.fn((url: string) => {
      result.redirect = { url };
      resolve(result);
    });

    strategy.pass = vi.fn(() => {
      result.pass = {};
      resolve(result);
    });

    strategy.error = vi.fn((error: Error) => {
      result.error = { error };
      resolve(result);
    });

    // Execute strategy authentication
    strategy.authenticate(request);
  });
}

// Custom matchers implementation
expect.extend({
  toAuthenticate(received: StrategyResult) {
    const pass = received.success !== undefined;
    return {
      pass,
      message: () =>
        pass ? `Expected strategy not to authenticate` : `Expected strategy to authenticate but it failed`,
    };
  },

  toFail(received: StrategyResult, expectedChallenge?: string, expectedStatus?: number) {
    const pass = received.fail !== undefined;
    if (!pass) {
      return {
        pass,
        message: () => `Expected strategy to fail but it succeeded`,
      };
    }

    const failResult = received.fail!;
    let challengeMatch = true;
    let statusMatch = true;

    if (expectedChallenge !== undefined) {
      challengeMatch = failResult.challenge === expectedChallenge;
    }

    if (expectedStatus !== undefined) {
      statusMatch = failResult.status === expectedStatus;
    }

    const actualPass = pass && challengeMatch && statusMatch;

    return {
      pass: actualPass,
      message: () => {
        if (!challengeMatch) {
          return `Expected challenge "${expectedChallenge}" but got "${failResult.challenge}"`;
        }
        if (!statusMatch) {
          return `Expected status ${expectedStatus} but got ${failResult.status}`;
        }
        return `Expected strategy to fail with specific parameters`;
      },
    };
  },

  toRedirect(received: StrategyResult, expectedUrl?: string) {
    const pass = received.redirect !== undefined;
    if (!pass) {
      return {
        pass,
        message: () => `Expected strategy to redirect but it didn't`,
      };
    }

    if (expectedUrl !== undefined) {
      const redirectResult = received.redirect!;
      const urlMatch = redirectResult.url === expectedUrl;
      return {
        pass: urlMatch,
        message: () =>
          urlMatch
            ? `Expected strategy not to redirect to "${expectedUrl}"`
            : `Expected redirect to "${expectedUrl}" but got "${redirectResult.url}"`,
      };
    }

    return {
      pass: true,
      message: () => `Expected strategy not to redirect`,
    };
  },

  toPass(received: StrategyResult) {
    const pass = received.pass !== undefined;
    return {
      pass,
      message: () => (pass ? `Expected strategy not to pass` : `Expected strategy to pass but it didn't`),
    };
  },

  toError(received: StrategyResult, expectedError?: Error) {
    const pass = received.error !== undefined;
    if (!pass) {
      return {
        pass,
        message: () => `Expected strategy to error but it didn't`,
      };
    }

    if (expectedError !== undefined) {
      const errorResult = received.error!;
      const errorMatch = errorResult.error === expectedError;
      return {
        pass: errorMatch,
        message: () =>
          errorMatch
            ? `Expected strategy not to error with specific error`
            : `Expected specific error but got different error`,
      };
    }

    return {
      pass: true,
      message: () => `Expected strategy not to error`,
    };
  },
});
