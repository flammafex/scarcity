/**
 * Base Command class for CLI commands
 */

export interface CommandOptions {
  [key: string]: string | boolean | number | undefined;
}

export abstract class Command {
  protected name: string;
  protected description: string;

  constructor(name: string, description: string) {
    this.name = name;
    this.description = description;
  }

  /**
   * Execute the command
   */
  abstract execute(args: string[]): Promise<void>;

  /**
   * Show help for this command
   */
  abstract showHelp(): void;

  /**
   * Parse command-line arguments into options
   */
  protected parseArgs(args: string[]): { positional: string[]; options: CommandOptions } {
    const positional: string[] = [];
    const options: CommandOptions = {};

    for (let i = 0; i < args.length; i++) {
      const arg = args[i];

      if (arg.startsWith('--')) {
        // Long option
        const key = arg.slice(2);
        const nextArg = args[i + 1];

        if (nextArg && !nextArg.startsWith('-')) {
          // Option with value
          options[key] = nextArg;
          i++;
        } else {
          // Boolean flag
          options[key] = true;
        }
      } else if (arg.startsWith('-') && arg.length === 2) {
        // Short option
        const key = arg.slice(1);
        const nextArg = args[i + 1];

        if (nextArg && !nextArg.startsWith('-')) {
          options[key] = nextArg;
          i++;
        } else {
          options[key] = true;
        }
      } else {
        // Positional argument
        positional.push(arg);
      }
    }

    return { positional, options };
  }

  /**
   * Require a positional argument
   */
  protected requireArg(positional: string[], index: number, name: string): string {
    if (!positional[index]) {
      throw new Error(`Missing required argument: ${name}`);
    }
    return positional[index];
  }

  /**
   * Get an option value with default
   */
  protected getOption<T = string>(
    options: CommandOptions,
    key: string,
    defaultValue?: T
  ): T | undefined {
    const value = options[key];
    return value !== undefined ? (value as T) : defaultValue;
  }

  /**
   * Require an option value
   */
  protected requireOption(options: CommandOptions, key: string, name?: string): string {
    const value = options[key];
    if (value === undefined || value === true) {
      throw new Error(`Missing required option: --${name || key}`);
    }
    return String(value);
  }
}
