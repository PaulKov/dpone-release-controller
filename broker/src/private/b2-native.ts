import type { B2WriteResult, B2Writer } from "../b2";
import { BrokerError } from "../errors";
import type { JsonObject } from "../types";
import {
  type B2NativeConfig,
  type B2Session,
  type ProviderFetch,
  authorizedPost,
  integerField,
  objectField,
  providerJson,
  providerUploadUrl,
  requireExactSseB2,
  requireLiteral,
  requireProviderOk,
  safeFetch,
  stringField,
  validateObjectInput,
} from "./b2-native-provider";
import { B2SessionProvider } from "./b2-native-session";

const WRITER_CAPABILITIES = ["writeFiles"] as const;

export type { B2NativeConfig } from "./b2-native-provider";
export { B2NativeVersionObserver } from "./b2-native-observer";

export class B2NativeWriter implements B2Writer {
  private readonly sessions: B2SessionProvider;

  public constructor(
    private readonly config: B2NativeConfig,
    private readonly providerFetch: ProviderFetch = fetch,
  ) {
    this.sessions = new B2SessionProvider(config, WRITER_CAPABILITIES, providerFetch);
  }

  public async uploadExact(input: {
    readonly canonicalBytes: Uint8Array;
    readonly contentSha1: string;
    readonly digest: string;
    readonly key: string;
  }): Promise<B2WriteResult> {
    validateObjectInput(input, this.config.prefix);
    const session = await this.sessions.authorize();
    const uploadTarget = await this.getUploadTarget(session);
    const response = await safeFetch(
      this.providerFetch,
      uploadTarget.url,
      {
        body: Uint8Array.from(input.canonicalBytes).buffer,
        headers: {
          authorization: uploadTarget.token,
          "content-length": String(input.canonicalBytes.byteLength),
          "content-type": "application/json",
          "x-bz-content-sha1": input.contentSha1,
          "x-bz-file-name": encodeURIComponent(input.key),
          "x-bz-info-dpone-sha256": encodeURIComponent(input.digest),
          "x-bz-server-side-encryption": "AES256",
        },
        method: "POST",
        redirect: "error",
      },
      "B2_UPLOAD_UNAVAILABLE",
    );
    await requireProviderOk(response, "B2_UPLOAD_FAILED");
    const result = await providerJson(response, 16_384, "B2_UPLOAD_RESPONSE_INVALID");
    requireLiteral(result, "accountId", session.accountId, "B2_UPLOAD_RESPONSE_INVALID");
    requireLiteral(result, "action", "upload", "B2_UPLOAD_RESPONSE_INVALID");
    requireLiteral(result, "bucketId", this.config.bucketId, "B2_UPLOAD_RESPONSE_INVALID");
    requireLiteral(result, "contentType", "application/json", "B2_UPLOAD_RESPONSE_INVALID");
    requireLiteral(result, "fileName", input.key, "B2_UPLOAD_RESPONSE_INVALID");
    requireLiteral(result, "contentSha1", input.contentSha1, "B2_UPLOAD_RESPONSE_INVALID");
    if (integerField(result, "contentLength") !== input.canonicalBytes.byteLength) {
      throw new BrokerError("B2_UPLOAD_RESPONSE_INVALID", 503, false);
    }
    const fileInfo = objectField(result, "fileInfo", "B2_UPLOAD_RESPONSE_INVALID");
    requireLiteral(fileInfo, "dpone-sha256", input.digest, "B2_UPLOAD_RESPONSE_INVALID");
    requireExactSseB2(result, "B2_UPLOAD_ENCRYPTION_INVALID");
    return { versionId: stringField(result, "fileId", 512) };
  }

  /** Redacted authorize-account observation; no bearer or application key leaves this class. */
  public async observeAuthorization(): Promise<JsonObject> {
    return (await this.sessions.authorize()).authorizationEvidence;
  }

  private async getUploadTarget(session: B2Session): Promise<{
    readonly token: string;
    readonly url: string;
  }> {
    const response = await authorizedPost(this.providerFetch, session, "b2_get_upload_url", {
      bucketId: this.config.bucketId,
    });
    const result = await providerJson(response, 16_384, "B2_UPLOAD_URL_RESPONSE_INVALID");
    requireLiteral(result, "bucketId", this.config.bucketId, "B2_UPLOAD_URL_RESPONSE_INVALID");
    return {
      token: stringField(result, "authorizationToken", 2048),
      url: providerUploadUrl(stringField(result, "uploadUrl", 4096), this.config.bucketId),
    };
  }
}

/** Native B2 observer isolated from the writer and all mutation capabilities. */
