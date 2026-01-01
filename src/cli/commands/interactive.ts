/**
 * Interactive command - Interactive REPL mode
 */

import { Command } from '../command.js';

export class InteractiveCommand extends Command {
  constructor() {
    super('interactive', 'Interactive REPL mode');
  }

  async execute(args: string[]): Promise<void> {
    const { positional, options } = this.parseArgs(args);

    if (options.help || options.h) {
      this.showHelp();
      return;
    }

    console.log('Interactive REPL mode implementation coming soon...');
    console.log('This will provide an interactive shell for Scarcity operations.');
  }

  showHelp(): void {
    console.log(`
USAGE:
  scar interactive [options]
  scar repl [options]

DESCRIPTION:
  Start an interactive REPL (Read-Eval-Print Loop) for Scarcity operations.
  This provides a shell-like interface for managing wallets, tokens, and more.

OPTIONS:
  -h, --help                 Show this help message

EXAMPLES:
  # Start interactive mode
  scar interactive

  # Use alias
  scar repl
`);
  }
}
