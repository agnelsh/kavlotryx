// Kavlotryx public demo on Cloudflare Containers.
//
// One Durable Object ("demo") owns one container, so every visitor sees the
// same data. The container sleeps after INACTIVITY_TIMEOUT_MS without requests
// and starts again on the next one, with fresh sample data from the image.
import { DurableObject } from "cloudflare:workers";

interface Env {
	DEMO: DurableObjectNamespace<KavlotryxDemo>;
	PUBLIC_URL?: string; // e.g. https://demo.example.com; empty = the address of the first request
	KAVLO_API_TOKENS?: string; // secret, optional: private admin sign-in, "name:admin:<token>"
	KAVLO_SESSION_SECRET?: string; // secret, optional: keeps that sign-in across restarts
}

const PORT = 8080;
const INACTIVITY_TIMEOUT_MS = 10 * 60 * 1000;

export class KavlotryxDemo extends DurableObject<Env> {
	private starting: Promise<void> | undefined;

	constructor(ctx: DurableObjectState, env: Env) {
		super(ctx, env);
		const container = ctx.container!;
		if (container.running) {
			void ctx.blockConcurrencyWhile(() => container.setInactivityTimeout(INACTIVITY_TIMEOUT_MS));
		}
	}

	async fetch(request: Request): Promise<Response> {
		const publicUrl = this.env.PUBLIC_URL || new URL(request.url).origin;
		// Concurrent requests share one start and readiness check.
		this.starting ??= this.startAndWait(publicUrl).finally(() => {
			this.starting = undefined;
		});
		await this.starting;

		const url = new URL(request.url);
		url.protocol = "http:";
		url.host = "container";
		const forwarded = new Request(url, request);
		forwarded.headers.delete("host");
		return this.ctx.container!.getTcpPort(PORT).fetch(forwarded);
	}

	private async startAndWait(publicUrl: string): Promise<void> {
		const container = this.ctx.container!;
		if (!container.running) {
			const env: Record<string, string> = { KAVLO_PUBLIC_URL: publicUrl };
			if (this.env.KAVLO_API_TOKENS) env.KAVLO_API_TOKENS = this.env.KAVLO_API_TOKENS;
			if (this.env.KAVLO_SESSION_SECRET) env.KAVLO_SESSION_SECRET = this.env.KAVLO_SESSION_SECRET;
			// The demo needs no outbound Internet: the tracker is a local fake and the
			// connectors read snapshots baked into the image.
			container.start({ enableInternet: false, env });
		}
		await container.setInactivityTimeout(INACTIVITY_TIMEOUT_MS);

		const port = container.getTcpPort(PORT);
		let lastError: unknown;
		for (let attempt = 0; attempt < 150; attempt++) {
			try {
				const response = await port.fetch("http://container/healthz", { signal: AbortSignal.timeout(1000) });
				await response.body?.cancel();
				if (response.ok) return;
				lastError = new Error(`health check returned ${response.status}`);
			} catch (error) {
				lastError = error;
			}
			await scheduler.wait(200);
		}
		throw new Error(`Kavlotryx did not become ready on port ${PORT}`, { cause: lastError });
	}
}

export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		if (request.method !== "GET" && request.method !== "HEAD" && request.method !== "POST") {
			return new Response("Method not allowed", { status: 405 });
		}
		try {
			return await env.DEMO.getByName("demo").fetch(request);
		} catch (error) {
			console.error("demo container error", error);
			return new Response("The demo is waking up or unavailable. Try again in a few seconds.", {
				status: 503,
				headers: { "retry-after": "5", "content-type": "text/plain; charset=utf-8" },
			});
		}
	},
} satisfies ExportedHandler<Env>;
