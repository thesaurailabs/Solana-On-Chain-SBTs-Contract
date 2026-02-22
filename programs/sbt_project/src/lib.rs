use anchor_lang::prelude::*;
use anchor_spl::{
    associated_token::AssociatedToken,
    token_interface::{Mint, TokenAccount},
};
use spl_tlv_account_resolution::{
    account::ExtraAccountMeta, seeds::Seed, state::ExtraAccountMetaList,
};
use spl_transfer_hook_interface::instruction::ExecuteInstruction;
use anchor_lang::solana_program::program_pack::Pack;

declare_id!("SauRx3x2PxjCfiW38oucPbB1aU5gfDvqx6mr8SeUVyU");

pub const ADMIN_WALLET: Pubkey = pubkey!("3c1gFBMmZFrDTgUz2HH8yhhbfqibdwfK14QtHRiQLYE1");

#[program]
pub mod sbt_project {
    use super::*;

    /// Initialize the config PDA with the hardcoded admin wallet.
    /// Can only be called once (init constraint).
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let config = &mut ctx.accounts.config;
        config.admin_vault = ADMIN_WALLET;
        config.bump = ctx.bumps.config;
        msg!("Config initialized: admin = {}", ADMIN_WALLET);
        Ok(())
    }

    /// Initialize the extra account meta list for a mint's transfer hook.
    /// Only the admin wallet can call this.
    pub fn initialize_extra_account_meta_list(
        ctx: Context<InitializeExtraAccountMetaList>,
    ) -> Result<()> {
        // Admin gate
        require!(
            ctx.accounts.payer.key() == ADMIN_WALLET,
            SbtError::Unauthorized
        );

        let extra_metas = vec![
            // Config PDA
            ExtraAccountMeta::new_with_seeds(
                &[Seed::Literal {
                    bytes: b"config".to_vec(),
                }],
                false, // is_signer
                false, // is_writable
            )?,
        ];

        let account_size =
            ExtraAccountMetaList::size_of(extra_metas.len())? as u64;
        let lamports = Rent::get()?.minimum_balance(account_size as usize);

        let mint_key = ctx.accounts.mint.key();
        let seeds: &[&[u8]] = &[b"extra-account-metas", mint_key.as_ref()];
        let (_, bump) = Pubkey::find_program_address(seeds, &crate::ID);
        let signer_seeds: &[&[u8]] = &[b"extra-account-metas", mint_key.as_ref(), &[bump]];

        anchor_lang::system_program::create_account(
            CpiContext::new_with_signer(
                ctx.accounts.system_program.to_account_info(),
                anchor_lang::system_program::CreateAccount {
                    from: ctx.accounts.payer.to_account_info(),
                    to: ctx.accounts.extra_account_meta_list.to_account_info(),
                },
                &[signer_seeds],
            ),
            lamports,
            account_size,
            &crate::ID,
        )?;

        ExtraAccountMetaList::init::<ExecuteInstruction>(
            &mut ctx
                .accounts
                .extra_account_meta_list
                .try_borrow_mut_data()?,
            &extra_metas,
        )?;

        msg!("ExtraAccountMetaList initialized for mint {}", mint_key);
        Ok(())
    }

    /// Fallback for unrecognized instructions (required by transfer hook interface)
    pub fn fallback<'info>(
        _program_id: &Pubkey,
        accounts: &'info [AccountInfo<'info>],
        data: &[u8],
    ) -> Result<()> {
        let instruction = spl_transfer_hook_interface::instruction::TransferHookInstruction::unpack(data)?;
        match instruction {
            spl_transfer_hook_interface::instruction::TransferHookInstruction::Execute { amount } => {
                msg!("Fallback: Execute transfer hook");

                // Validate we have the right number of accounts
                // accounts: [source, mint, destination, owner, extra_account_meta_list, config]
                if accounts.len() < 6 {
                    return err!(SbtError::TransferForbidden);
                }

                // 1) Enforce fixed transfer amount of 1 (prevent sending > 1 at a time)
                if amount != 1 {
                    msg!("Error: Can only transfer exactly 1 SBT at a time");
                    return err!(SbtError::InvalidTransferAmount);
                }

                let source_token_info = &accounts[0];
                let destination_token_info = &accounts[2];
                let config_info = &accounts[5];

                // Deserialize SPL Token 2022 Accounts safely (ignoring extension padding)
                let source_token_data = source_token_info.data.borrow();
                let source_token = anchor_spl::token_interface::spl_token_2022::state::Account::unpack_from_slice(&source_token_data)
                    .map_err(|_| ProgramError::InvalidAccountData)?;

                let destination_token_data = destination_token_info.data.borrow();
                let destination_token = anchor_spl::token_interface::spl_token_2022::state::Account::unpack_from_slice(&destination_token_data)
                    .map_err(|_| ProgramError::InvalidAccountData)?;

                // Deserialize Config PDA
                let config = Config::try_deserialize(&mut &config_info.data.borrow()[..])
                    .map_err(|_| ProgramError::InvalidAccountData)?;

                // 2) Enforce max 1 SBT per wallet
                // Transfer Hooks execute *after* the Token program updates balances in memory.
                // If they are receiving their first 1 SBT, their balance is now exactly 1.
                // If they already hold an SBT, their balance will be > 1. Block the transfer.
                if destination_token.amount > 1 {
                    msg!("Error: Recipient wallet already holds this SBT tier");
                    return err!(SbtError::MaxOneSBTPerWallet);
                }

                // 3) Enforce soulbound (only admin can send)
                // The source token account's owner must be the admin wallet
                if source_token.owner != crate::ADMIN_WALLET {
                    msg!("Error: SBT is soulbound. Only the Admin can distribute it.");
                    return err!(SbtError::TransferForbidden);
                }

                msg!("Transfer allowed: 1 SBT from Admin to recipient");
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

// ============================================================================
// ACCOUNTS
// ============================================================================

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = payer,
        space = 8 + 32 + 1,
        seeds = [b"config"],
        bump
    )]
    pub config: Account<'info, Config>,

    #[account(mut)]
    pub payer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct InitializeExtraAccountMetaList<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    /// We use create_account manually because size is dynamic.
    /// CHECK: Validated by PDA seeds
    #[account(
        mut,
        seeds = [b"extra-account-metas", mint.key().as_ref()],
        bump,
    )]
    pub extra_account_meta_list: AccountInfo<'info>,

    pub mint: InterfaceAccount<'info, Mint>,
    pub system_program: Program<'info, System>,
    pub associated_token_program: Program<'info, AssociatedToken>,
}

#[derive(Accounts)]
pub struct TransferHook<'info> {
    pub source_token: InterfaceAccount<'info, TokenAccount>,
    pub mint: InterfaceAccount<'info, Mint>,
    pub destination_token: InterfaceAccount<'info, TokenAccount>,
    /// CHECK: Owner of the source token account
    pub owner: AccountInfo<'info>,

    /// CHECK: ExtraAccountMetaList PDA
    #[account(
        seeds = [b"extra-account-metas", mint.key().as_ref()],
        bump,
    )]
    pub extra_account_meta_list: AccountInfo<'info>,

    #[account(
        seeds = [b"config"],
        bump = config.bump,
    )]
    pub config: Account<'info, Config>,
}

// ============================================================================
// STATE
// ============================================================================

#[account]
pub struct Config {
    pub admin_vault: Pubkey,
    pub bump: u8,
}

// ============================================================================
// ERRORS
// ============================================================================

#[error_code]
pub enum SbtError {
    #[msg("TransferForbidden: SBTs are soulbound in nature and cannot be transferred.")]
    TransferForbidden,
    #[msg("Access Denied")]
    Unauthorized,
    #[msg("Can only transfer exactly 1 SBT at a time")]
    InvalidTransferAmount,
    #[msg("Maximum Limit Reached: Recipient wallet can own only 1 SBT / Tier.")]
    MaxOneSBTPerWallet,
}

use solana_security_txt::security_txt;

security_txt! {
    name: "SAURAI Soulbound Token Program",
    project_url: "https://saurs.ai",
    contacts: "email:reachout@saurs.ai",
    preferred_languages: "en",
    source_code: "https://github.com/thesaurailabs/Solana-On-Chain-SBTs-Contract",
    acknowledgements: "The SaurAI Labs",
    icon: "https://ipfs.io/ipfs/Qmbwdfd9BAbyPLJn3TixaTkKbSNZFLEa5cDam4Eev4eJHP"
}
