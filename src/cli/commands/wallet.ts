/**
 * Wallet command - Manage wallets and keys
 */

import { Command } from '../command.js';
import { WalletManager } from '../wallet.js';

export class WalletCommand extends Command {
  constructor() {
    super('wallet', 'Manage wallets and keys');
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

    const wallet = new WalletManager();

    switch (subcommand) {
      case 'create':
        await this.create(wallet, positional, options);
        break;

      case 'list':
        await this.list(wallet);
        break;

      case 'show':
        await this.show(wallet, positional, options);
        break;

      case 'import':
        await this.import(wallet, positional, options);
        break;

      case 'export':
        await this.export(wallet, positional, options);
        break;

      case 'delete':
        await this.delete(wallet, positional, options);
        break;

      case 'default':
        await this.setDefault(wallet, positional, options);
        break;

      default:
        console.error(`Unknown subcommand: ${subcommand}`);
        this.showHelp();
        process.exit(1);
    }
  }

  private async create(wallet: WalletManager, positional: string[], options: any): Promise<void> {
    const name = positional[1] || 'default';
    const setDefault = options.default !== false;

    try {
      const walletData = wallet.createWallet(name, setDefault);

      console.log('✅ Wallet created successfully!');
      console.log('');
      console.log(`Name:       ${walletData.name}`);
      console.log(`Public Key: ${walletData.publicKey}`);
      console.log('');
      console.log('⚠️  IMPORTANT: Back up your secret key!');
      console.log('');
      console.log(`Secret Key: ${walletData.secretKey}`);
      console.log('');
      console.log('Store this secret key safely. You will need it to access your tokens.');
      console.log('Anyone with this secret key can spend your tokens!');
      console.log('');

      if (setDefault) {
        console.log(`✓ Set as default wallet`);
      }
    } catch (error: any) {
      console.error(`Failed to create wallet: ${error.message}`);
      process.exit(1);
    }
  }

  private async list(wallet: WalletManager): Promise<void> {
    const wallets = wallet.listWallets();
    const defaultWallet = wallet.getDefaultWalletName();

    if (wallets.length === 0) {
      console.log('No wallets found. Create one with: scar wallet create');
      return;
    }

    console.log('');
    console.log('Wallets:');
    console.log('');

    for (const w of wallets) {
      const isDefault = w.name === defaultWallet ? ' (default)' : '';
      const date = new Date(w.created).toLocaleString();

      console.log(`  ${w.name}${isDefault}`);
      console.log(`    Public Key: ${w.publicKey}`);
      console.log(`    Created:    ${date}`);
      console.log('');
    }
  }

  private async show(wallet: WalletManager, positional: string[], options: any): Promise<void> {
    const name = positional[1];

    try {
      const walletData = wallet.getWallet(name);
      const isDefault = name === wallet.getDefaultWalletName() || (!name && wallet.getDefaultWalletName());
      const date = new Date(walletData.created).toLocaleString();

      console.log('');
      console.log(`Wallet: ${walletData.name}${isDefault ? ' (default)' : ''}`);
      console.log('');
      console.log(`Public Key: ${walletData.publicKey}`);
      console.log(`Created:    ${date}`);
      console.log('');

      if (options.secret) {
        console.log('⚠️  SECRET KEY (keep safe!):');
        console.log(walletData.secretKey);
        console.log('');
      } else {
        console.log('Use --secret to show secret key');
        console.log('');
      }
    } catch (error: any) {
      console.error(`Failed to show wallet: ${error.message}`);
      process.exit(1);
    }
  }

  private async import(wallet: WalletManager, positional: string[], options: any): Promise<void> {
    const name = this.requireArg(positional, 1, 'name');
    const secretKey = this.requireOption(options, 'secret', 'secret');
    const setDefault = options.default === true;

    try {
      const walletData = wallet.importWallet(name, secretKey as string, setDefault);

      console.log('✅ Wallet imported successfully!');
      console.log('');
      console.log(`Name:       ${walletData.name}`);
      console.log(`Public Key: ${walletData.publicKey}`);
      console.log('');

      if (setDefault) {
        console.log(`✓ Set as default wallet`);
      }
    } catch (error: any) {
      console.error(`Failed to import wallet: ${error.message}`);
      process.exit(1);
    }
  }

  private async export(wallet: WalletManager, positional: string[], options: any): Promise<void> {
    const name = positional[1];

    try {
      const secretKey = wallet.exportSecret(name);

      console.log('');
      console.log('⚠️  SECRET KEY (keep this safe!):');
      console.log('');
      console.log(secretKey);
      console.log('');
      console.log('Anyone with this secret key can spend your tokens!');
      console.log('');
    } catch (error: any) {
      console.error(`Failed to export wallet: ${error.message}`);
      process.exit(1);
    }
  }

  private async delete(wallet: WalletManager, positional: string[], options: any): Promise<void> {
    const name = this.requireArg(positional, 1, 'name');

    if (!options.confirm) {
      console.error('');
      console.error('⚠️  WARNING: This will permanently delete the wallet!');
      console.error('Make sure you have backed up the secret key.');
      console.error('');
      console.error('To confirm deletion, add --confirm flag');
      console.error('');
      process.exit(1);
    }

    try {
      wallet.deleteWallet(name);

      console.log('');
      console.log(`✅ Wallet '${name}' deleted`);
      console.log('');
    } catch (error: any) {
      console.error(`Failed to delete wallet: ${error.message}`);
      process.exit(1);
    }
  }

  private async setDefault(wallet: WalletManager, positional: string[], options: any): Promise<void> {
    const name = this.requireArg(positional, 1, 'name');

    try {
      wallet.setDefault(name);

      console.log('');
      console.log(`✅ Set '${name}' as default wallet`);
      console.log('');
    } catch (error: any) {
      console.error(`Failed to set default wallet: ${error.message}`);
      process.exit(1);
    }
  }

  showHelp(): void {
    console.log(`
USAGE:
  scar wallet <subcommand> [options]

SUBCOMMANDS:
  create [name]              Create a new wallet
  list                       List all wallets
  show [name]                Show wallet details
  import <name> --secret KEY Import wallet from secret key
  export [name]              Export wallet secret key
  delete <name> --confirm    Delete a wallet
  default <name>             Set default wallet

OPTIONS:
  --secret      Show/provide secret key
  --default     Set as default wallet
  --confirm     Confirm destructive operation
  -h, --help    Show this help message

EXAMPLES:
  # Create a new wallet
  scar wallet create

  # Create a named wallet
  scar wallet create alice

  # List all wallets
  scar wallet list

  # Show wallet with secret
  scar wallet show alice --secret

  # Import a wallet
  scar wallet import bob --secret 0x1234...

  # Export wallet secret
  scar wallet export alice

  # Set default wallet
  scar wallet default alice

  # Delete a wallet
  scar wallet delete bob --confirm
`);
  }
}
