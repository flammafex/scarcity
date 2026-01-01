/**
 * Config command - Configuration management
 */

import { Command } from '../command.js';
import { ConfigManager } from '../config.js';

export class ConfigCommand extends Command {
  constructor() {
    super('config', 'Configuration management');
  }

  async execute(args: string[]): Promise<void> {
    const { positional, options } = this.parseArgs(args);

    if (options.help || options.h) {
      this.showHelp();
      return;
    }

    const subcommand = positional[0];

    if (!subcommand) {
      this.showHelp();
      return;
    }

    const config = new ConfigManager();

    switch (subcommand) {
      case 'show':
        await this.show(config);
        break;

      case 'get':
        await this.get(config, positional);
        break;

      case 'set':
        await this.set(config, positional);
        break;

      case 'reset':
        await this.reset(config, options);
        break;

      default:
        console.error(`Unknown subcommand: ${subcommand}`);
        this.showHelp();
        process.exit(1);
    }
  }

  private async show(config: ConfigManager): Promise<void> {
    const cfg = config.getAll();

    console.log('');
    console.log('Scarcity Configuration');
    console.log('======================');
    console.log('');
    console.log('Witness:');
    console.log(`  Gateway URL: ${cfg.witness.gatewayUrl}`);
    console.log(`  Network ID:  ${cfg.witness.networkId}`);
    console.log('');
    console.log('Freebird:');
    console.log(`  Issuer Endpoints:`);
    cfg.freebird.issuerEndpoints.forEach((url, i) => {
      console.log(`    [${i + 1}] ${url}`);
    });
    console.log(`  Verifier URL: ${cfg.freebird.verifierUrl}`);
    console.log('');
    console.log('HyperToken:');
    console.log(`  Relay URL: ${cfg.hypertoken.relayUrl}`);
    console.log('');
    console.log('Tor:');
    console.log(`  Enabled:    ${cfg.tor.enabled}`);
    console.log(`  Proxy Host: ${cfg.tor.proxyHost}`);
    console.log(`  Proxy Port: ${cfg.tor.proxyPort}`);
    console.log('');
    console.log(`Config file: ~/.scarcity/config.json`);
    console.log('');
  }

  private async get(config: ConfigManager, positional: string[]): Promise<void> {
    const key = this.requireArg(positional, 1, 'key');

    try {
      const value = config.get(key);

      if (value === undefined) {
        console.error(`Configuration key '${key}' not found`);
        process.exit(1);
      }

      if (typeof value === 'object') {
        console.log(JSON.stringify(value, null, 2));
      } else {
        console.log(value);
      }
    } catch (error: any) {
      console.error(`Failed to get config: ${error.message}`);
      process.exit(1);
    }
  }

  private async set(config: ConfigManager, positional: string[]): Promise<void> {
    const key = this.requireArg(positional, 1, 'key');
    const value = this.requireArg(positional, 2, 'value');

    try {
      // Try to parse as JSON for boolean/number values
      let parsedValue: any = value;

      if (value === 'true') {
        parsedValue = true;
      } else if (value === 'false') {
        parsedValue = false;
      } else if (!isNaN(Number(value)) && value.trim() !== '') {
        parsedValue = Number(value);
      }

      config.set(key, parsedValue);

      console.log('');
      console.log(`✅ Configuration updated`);
      console.log('');
      console.log(`${key} = ${parsedValue}`);
      console.log('');
    } catch (error: any) {
      console.error(`Failed to set config: ${error.message}`);
      process.exit(1);
    }
  }

  private async reset(config: ConfigManager, options: any): Promise<void> {
    if (!options.confirm) {
      console.error('');
      console.error('⚠️  WARNING: This will reset all configuration to defaults!');
      console.error('');
      console.error('To confirm reset, add --confirm flag');
      console.error('');
      process.exit(1);
    }

    try {
      config.reset();

      console.log('');
      console.log('✅ Configuration reset to defaults');
      console.log('');
    } catch (error: any) {
      console.error(`Failed to reset config: ${error.message}`);
      process.exit(1);
    }
  }

  showHelp(): void {
    console.log(`
USAGE:
  scar config <subcommand> [options]

SUBCOMMANDS:
  show                       Show all configuration
  get <key>                  Get configuration value
  set <key> <value>          Set configuration value
  reset                      Reset to defaults

CONFIGURATION KEYS:
  witness.gatewayUrl         Witness gateway URL
  witness.networkId          Witness network ID
  freebird.issuerUrl         Freebird issuer URL
  freebird.verifierUrl       Freebird verifier URL
  hypertoken.relayUrl        HyperToken relay URL
  tor.enabled                Enable Tor (true/false)
  tor.proxyHost              Tor SOCKS5 proxy host
  tor.proxyPort              Tor SOCKS5 proxy port

OPTIONS:
  --confirm                  Confirm destructive operation
  -h, --help                 Show this help message

EXAMPLES:
  # Show all config
  scar config show

  # Get a value
  scar config get witness.gatewayUrl

  # Set a value
  scar config set witness.gatewayUrl http://localhost:8080

  # Set network ID
  scar config set witness.networkId scarcity-mainnet

  # Enable Tor
  scar config set tor.enabled true

  # Reset config
  scar config reset --confirm
`);
  }
}
