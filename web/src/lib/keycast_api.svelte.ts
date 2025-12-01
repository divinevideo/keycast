import { NDKEvent, NDKKind } from "@nostr-dev-kit/ndk";
import { getContext, setContext } from "svelte";
import ndk from "./ndk.svelte";

export class KeycastApi {
    private baseUrl: string;
    private defaultHeaders: HeadersInit;

    constructor() {
        const apiDomain =
            import.meta.env.VITE_DOMAIN || "http://localhost:3000";
        const domain = apiDomain.startsWith("http")
            ? apiDomain
            : `https://${apiDomain}`;
        this.baseUrl = `${domain}/api`;
        this.defaultHeaders = {
            "Content-Type": "application/json",
            Accept: "application/json",
        };
    }

    private async request<T>(
        endpoint: string,
        options: RequestInit = {},
    ): Promise<T> {
        const url = `${this.baseUrl}${endpoint}`;
        const headers = { ...this.defaultHeaders, ...options.headers };

        const response = await fetch(url, {
            ...options,
            headers,
            credentials: options.credentials || 'include'  // Include cookies by default
        });

        if (!response.ok) {
            // Try to get the error message from the response body
            let errorMessage: string;
            try {
                const errorBody = await response.json();
                errorMessage = errorBody.error || errorBody.message || `Something went wrong. Please try again.`;
            } catch {
                // If we can't parse JSON, use a generic message
                errorMessage = 'Something went wrong. Please try again.';
            }
            throw new Error(errorMessage);
        }

        if (response.status === 204) {
            return null as T;
        }

        return response.json() as Promise<T>;
    }

    async get<T>(
        endpoint: string,
        options: {
            headers?: HeadersInit;
            params?: Record<string, string>;
            credentials?: RequestCredentials;
        } = {},
    ): Promise<T> {
        const url = options.params
            ? `${endpoint}?${new URLSearchParams(options.params)}`
            : endpoint;
        return this.request<T>(url, { headers: options.headers, credentials: options.credentials });
    }

    async post<T>(
        endpoint: string,
        data?: unknown,
        options: { headers?: HeadersInit } = {},
    ): Promise<T> {
        return this.request<T>(endpoint, {
            method: "POST",
            body: data ? JSON.stringify(data) : undefined,
            headers: options.headers,
        });
    }

    async put<T>(
        endpoint: string,
        data?: unknown,
        options: { headers?: HeadersInit } = {},
    ): Promise<T> {
        return this.request<T>(endpoint, {
            method: "PUT",
            body: data ? JSON.stringify(data) : undefined,
            headers: options.headers,
        });
    }

    async delete<T>(
        endpoint: string,
        options: { headers?: HeadersInit } = {},
    ): Promise<T> {
        return this.request<T>(endpoint, {
            method: "DELETE",
            headers: options.headers,
        });
    }

    async buildUnsignedAuthEvent(
        url: string,
        method: "GET" | "POST" | "PUT" | "DELETE",
        pubkey: string,
        body?: string,
    ): Promise<NDKEvent | null> {
        const authEvent: NDKEvent = new NDKEvent(ndk, {
            content: "",
            kind: NDKKind.HttpAuth,
            pubkey,
            created_at: Math.floor(Date.now() / 1000),
            tags: [
                ["u", `${this.baseUrl}${url}`],
                ["method", `${method}`],
            ],
        });

        let hashedPayload: string | undefined = undefined;
        if (body) {
            const buffer = await crypto.subtle.digest(
                "SHA-256",
                new TextEncoder().encode(body),
            );
            hashedPayload = Array.from(new Uint8Array(buffer))
                .map((b) => b.toString(16).padStart(2, "0"))
                .join("");
        }

        if (hashedPayload) {
            authEvent.tags.push(["payload", hashedPayload]);
        }

        return authEvent;
    }
}

const API_CONTEXT_KEY = Symbol("API");

export function initApi() {
    return setContext(API_CONTEXT_KEY, new KeycastApi());
}

export function getApi() {
    return getContext<ReturnType<typeof initApi>>(API_CONTEXT_KEY);
}
