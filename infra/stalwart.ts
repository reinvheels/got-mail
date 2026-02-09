import * as pulumi from "@pulumi/pulumi";

// ---------------------------------------------------------------------------
// Connection
// ---------------------------------------------------------------------------

interface StalwartConnection {
    baseUrl: string;
    apiKey?: string;
    username?: string;
    password?: string;
}

function getConn(props: Record<string, any>): StalwartConnection {
    return {
        baseUrl: props.baseUrl,
        apiKey: props.apiKey,
        username: props.username,
        password: props.password,
    };
}

async function stalwartFetch(
    conn: StalwartConnection,
    method: string,
    path: string,
    body?: unknown,
): Promise<any> {
    const headers: Record<string, string> = {
        "Content-Type": "application/json",
    };
    if (conn.apiKey) {
        headers["Authorization"] = `Bearer ${conn.apiKey}`;
    } else if (conn.username && conn.password) {
        const creds = Buffer.from(`${conn.username}:${conn.password}`).toString("base64");
        headers["Authorization"] = `Basic ${creds}`;
    }

    const url = `${conn.baseUrl}${path}`;
    const resp = await fetch(url, {
        method,
        headers,
        body: body ? JSON.stringify(body) : undefined,
    });

    if (!resp.ok) {
        const text = await resp.text();
        throw new Error(`Stalwart API ${method} ${path} → ${resp.status}: ${text}`);
    }

    const text = await resp.text();
    return text ? JSON.parse(text) : {};
}

// ---------------------------------------------------------------------------
// Domain
// ---------------------------------------------------------------------------

export interface DomainArgs {
    /** Stalwart base URL, e.g. https://mail.example.com */
    baseUrl: pulumi.Input<string>;
    /** Bearer token for API auth */
    apiKey?: pulumi.Input<string>;
    /** Basic auth username (alternative to apiKey) */
    username?: pulumi.Input<string>;
    /** Basic auth password (alternative to apiKey) */
    password?: pulumi.Input<string>;
    /** Domain name, e.g. example.com */
    domainName: pulumi.Input<string>;
    /** Human-readable description */
    description?: pulumi.Input<string>;
}

interface DomainState {
    baseUrl: string;
    apiKey?: string;
    username?: string;
    password?: string;
    domainName: string;
    description: string;
    stalwartId: number;
}

const domainProvider: pulumi.dynamic.ResourceProvider = {
    async create(inputs: DomainState): Promise<pulumi.dynamic.CreateResult> {
        const conn = getConn(inputs);
        const resp = await stalwartFetch(conn, "POST", "/api/principal", {
            type: "domain",
            name: inputs.domainName,
            description: inputs.description || "",
            quota: 0,
            secrets: [],
            emails: [],
            urls: [],
            memberOf: [],
            roles: [],
            lists: [],
            members: [],
            enabledPermissions: [],
            disabledPermissions: [],
            externalMembers: [],
        });
        return {
            id: inputs.domainName,
            outs: { ...inputs, stalwartId: resp.data },
        };
    },

    async read(id: string, props: DomainState): Promise<pulumi.dynamic.ReadResult> {
        const conn = getConn(props);
        try {
            const resp = await stalwartFetch(conn, "GET", `/api/principal/${encodeURIComponent(id)}`);
            if (resp.error === "notFound" || !resp.data) {
                return { id: "", props: undefined as any };
            }
            return {
                id,
                props: {
                    ...props,
                    domainName: resp.data.name,
                    description: resp.data.description ?? props.description ?? "",
                    stalwartId: resp.data.id,
                },
            };
        } catch (e: any) {
            if (e.message?.includes("404") || e.message?.includes("notFound")) {
                return { id: "", props: undefined as any };
            }
            throw e;
        }
    },

    async update(id: string, olds: DomainState, news: DomainState): Promise<pulumi.dynamic.UpdateResult> {
        const conn = getConn(news);
        const patches: { action: string; field: string; value: unknown }[] = [];

        if (olds.description !== news.description) {
            patches.push({ action: "set", field: "description", value: news.description || "" });
        }

        if (patches.length > 0) {
            await stalwartFetch(conn, "PATCH", `/api/principal/${encodeURIComponent(id)}`, patches);
        }

        return { outs: { ...news, stalwartId: olds.stalwartId } };
    },

    async delete(id: string, props: DomainState): Promise<void> {
        const conn = getConn(props);
        try {
            await stalwartFetch(conn, "DELETE", `/api/principal/${encodeURIComponent(id)}`);
        } catch (e: any) {
            if (!e.message?.includes("404")) throw e;
        }
    },

    async diff(_id: string, olds: DomainState, news: DomainState): Promise<pulumi.dynamic.DiffResult> {
        if (olds.domainName !== news.domainName) {
            return { changes: true, replaces: ["domainName"], deleteBeforeReplace: true };
        }
        const changes = olds.description !== news.description;
        return { changes };
    },
};

export class Domain extends pulumi.dynamic.Resource {
    public readonly domainName!: pulumi.Output<string>;
    public readonly description!: pulumi.Output<string>;
    public readonly stalwartId!: pulumi.Output<number>;

    constructor(name: string, args: DomainArgs, opts?: pulumi.CustomResourceOptions) {
        super(
            domainProvider,
            name,
            { ...args, stalwartId: undefined },
            opts,
        );
    }
}

// ---------------------------------------------------------------------------
// Account
// ---------------------------------------------------------------------------

export interface AccountArgs {
    /** Stalwart base URL */
    baseUrl: pulumi.Input<string>;
    /** Bearer token for API auth */
    apiKey?: pulumi.Input<string>;
    /** Basic auth username (alternative to apiKey) */
    username?: pulumi.Input<string>;
    /** Basic auth password (alternative to apiKey) */
    password?: pulumi.Input<string>;
    /** Login username, e.g. alice */
    accountName: pulumi.Input<string>;
    /** Display name / full name */
    description?: pulumi.Input<string>;
    /** Account password (plaintext — Stalwart hashes on storage) */
    accountPassword: pulumi.Input<string>;
    /** Email addresses. First is primary. */
    emails: pulumi.Input<pulumi.Input<string>[]>;
    /** Storage quota in bytes (0 = unlimited) */
    quota?: pulumi.Input<number>;
    /** Roles, e.g. ["user"] or ["admin"] */
    roles?: pulumi.Input<pulumi.Input<string>[]>;
    /** Groups this account belongs to */
    memberOf?: pulumi.Input<pulumi.Input<string>[]>;
}

interface AccountState {
    baseUrl: string;
    apiKey?: string;
    username?: string;
    password?: string;
    accountName: string;
    description: string;
    accountPassword: string;
    emails: string[];
    quota: number;
    roles: string[];
    memberOf: string[];
    stalwartId: number;
}

const accountProvider: pulumi.dynamic.ResourceProvider = {
    async create(inputs: AccountState): Promise<pulumi.dynamic.CreateResult> {
        const conn = getConn(inputs);
        const principalName = inputs.emails[0];
        const resp = await stalwartFetch(conn, "POST", "/api/principal", {
            type: "individual",
            name: principalName,
            description: inputs.description || "",
            secrets: [inputs.accountPassword],
            emails: inputs.emails,
            quota: inputs.quota || 0,
            roles: inputs.roles || ["user"],
            memberOf: inputs.memberOf || [],
            urls: [],
            lists: [],
            members: [],
            enabledPermissions: [],
            disabledPermissions: [],
            externalMembers: [],
        });
        return {
            id: principalName,
            outs: { ...inputs, stalwartId: resp.data },
        };
    },

    async read(id: string, props: AccountState): Promise<pulumi.dynamic.ReadResult> {
        const conn = getConn(props);
        try {
            const resp = await stalwartFetch(conn, "GET", `/api/principal/${encodeURIComponent(id)}`);
            if (resp.error === "notFound" || !resp.data) {
                return { id: "", props: undefined as any };
            }
            const d = resp.data;
            return {
                id,
                props: {
                    ...props,
                    accountName: props.accountName,
                    description: d.description || "",
                    // Keep the input password — we can't reverse the hash
                    accountPassword: props.accountPassword,
                    emails: Array.isArray(d.emails) ? d.emails : d.emails ? [d.emails] : [],
                    quota: d.quota ?? props.quota ?? 0,
                    roles: d.roles ?? props.roles ?? [],
                    memberOf: d.memberOf ?? props.memberOf ?? [],
                    stalwartId: d.id,
                },
            };
        } catch (e: any) {
            if (e.message?.includes("404") || e.message?.includes("notFound")) {
                return { id: "", props: undefined as any };
            }
            throw e;
        }
    },

    async update(id: string, olds: AccountState, news: AccountState): Promise<pulumi.dynamic.UpdateResult> {
        const conn = getConn(news);
        // Always PATCH non-secret fields to ensure consistency, even on spurious updates
        const patches: { action: string; field: string; value: unknown }[] = [
            { action: "set", field: "description", value: news.description || "" },
            { action: "set", field: "emails", value: news.emails },
            { action: "set", field: "quota", value: news.quota || 0 },
            { action: "set", field: "roles", value: news.roles || ["user"] },
            { action: "set", field: "memberOf", value: news.memberOf || [] },
        ];

        // Only update password when it actually changed
        if (olds.accountPassword !== news.accountPassword) {
            patches.push({ action: "set", field: "secrets", value: [news.accountPassword] });
        }

        await stalwartFetch(conn, "PATCH", `/api/principal/${encodeURIComponent(id)}`, patches);

        return { outs: { ...news, stalwartId: olds.stalwartId } };
    },

    async delete(id: string, props: AccountState): Promise<void> {
        const conn = getConn(props);
        try {
            await stalwartFetch(conn, "DELETE", `/api/principal/${encodeURIComponent(id)}`);
        } catch (e: any) {
            if (!e.message?.includes("404")) throw e;
        }
    },

    async diff(_id: string, olds: AccountState, news: AccountState): Promise<pulumi.dynamic.DiffResult> {
        if (olds.accountName !== news.accountName || olds.emails[0] !== news.emails[0]) {
            return { changes: true, replaces: ["accountName", "emails"], deleteBeforeReplace: true };
        }

        const changes =
            olds.description !== news.description ||
            olds.accountPassword !== news.accountPassword ||
            JSON.stringify(olds.emails.slice(1)) !== JSON.stringify(news.emails.slice(1)) ||
            (olds.quota || 0) !== (news.quota || 0) ||
            JSON.stringify(olds.roles) !== JSON.stringify(news.roles) ||
            JSON.stringify(olds.memberOf) !== JSON.stringify(news.memberOf);

        return { changes };
    },
};

export class Account extends pulumi.dynamic.Resource {
    public readonly accountName!: pulumi.Output<string>;
    public readonly description!: pulumi.Output<string>;
    public readonly emails!: pulumi.Output<string[]>;
    public readonly quota!: pulumi.Output<number>;
    public readonly roles!: pulumi.Output<string[]>;
    public readonly memberOf!: pulumi.Output<string[]>;
    public readonly stalwartId!: pulumi.Output<number>;

    constructor(name: string, args: AccountArgs, opts?: pulumi.CustomResourceOptions) {
        super(
            accountProvider,
            name,
            { ...args, stalwartId: undefined },
            opts,
        );
    }
}
