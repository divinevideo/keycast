import { KeycastApi } from '$lib/keycast_api.svelte';

export interface AccountStatus {
    email: string;
    email_verified: boolean;
    has_password: boolean;
    public_key: string;
}

let accountStatus: AccountStatus | null = $state(null);
let loading = $state(false);
let error = $state<string | null>(null);

export function getAccountStatus(): AccountStatus | null {
    return accountStatus;
}

export function isEmailVerified(): boolean {
    return accountStatus?.email_verified ?? false;
}

export function isLoading(): boolean {
    return loading;
}

export function getError(): string | null {
    return error;
}

export async function fetchAccountStatus(): Promise<AccountStatus | null> {
    loading = true;
    error = null;

    try {
        const api = new KeycastApi();
        const status = await api.get<AccountStatus>('/user/account');
        accountStatus = status;
        return status;
    } catch (e: any) {
        console.error('Failed to fetch account status:', e);
        error = e.message || 'Failed to fetch account status';
        return null;
    } finally {
        loading = false;
    }
}

export function clearAccountStatus(): void {
    accountStatus = null;
    loading = false;
    error = null;
}
