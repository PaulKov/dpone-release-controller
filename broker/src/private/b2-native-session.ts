import { BrokerError } from "../errors";
import { digestDomain } from "../identity";
import type { JsonObject } from "../types";
import {
  type B2NativeConfig,
  type B2Session,
  type ProviderFetch,
  arrayField,
  objectField,
  providerBaseUrl,
  providerJsonCapture,
  providerObject,
  requireProviderOk,
  safeFetch,
  sameSet,
  stringArrayField,
  stringField,
  validateConfig,
} from "./b2-native-provider";

const AUTHORIZE_URL = "https://api.backblazeb2.com/b2api/v4/b2_authorize_account";
const PROVIDER_JSON_LIMIT = 65_536;

export class B2SessionProvider {
  public constructor(
    private readonly config: B2NativeConfig,
    private readonly expectedCapabilities: readonly string[],
    private readonly providerFetch: ProviderFetch,
  ) {
    validateConfig(config);
  }

  public async authorize(): Promise<B2Session> {
    const basic = btoa(`${this.config.keyId}:${this.config.applicationKey}`);
    const response = await safeFetch(
      this.providerFetch,
      AUTHORIZE_URL,
      {
        headers: { authorization: `Basic ${basic}` },
        method: "GET",
        redirect: "error",
      },
      "B2_AUTHORIZE_UNAVAILABLE",
    );
    await requireProviderOk(response, "B2_AUTHORIZE_FAILED");
    const captured = await providerJsonCapture(
      response,
      PROVIDER_JSON_LIMIT,
      "B2_AUTHORIZE_RESPONSE_INVALID",
    );
    const root = captured.value;
    // Release recovery can outlive an ordinary key rotation window. A live A0
    // therefore admits only non-expiring, bucket-scoped application keys; key
    // rotation is represented by a new private Worker version and activation
    // epoch rather than by silently changing a credential underneath an epoch.
    if (
      !Object.prototype.hasOwnProperty.call(root, "applicationKeyExpirationTimestamp") ||
      root.applicationKeyExpirationTimestamp !== null
    ) {
      throw new BrokerError("B2_APPLICATION_KEY_EXPIRY_INVALID", 503, false);
    }
    const apiInfo = objectField(root, "apiInfo", "B2_AUTHORIZE_RESPONSE_INVALID");
    const storage = objectField(apiInfo, "storageApi", "B2_AUTHORIZE_RESPONSE_INVALID");
    const allowed = objectField(storage, "allowed", "B2_AUTHORIZE_RESPONSE_INVALID");
    const capabilities = stringArrayField(allowed, "capabilities", "B2_AUTHORIZE_RESPONSE_INVALID");
    if (!sameSet(capabilities, this.expectedCapabilities)) {
      throw new BrokerError("B2_CAPABILITY_SCOPE_INVALID", 503, false);
    }
    if (stringField(allowed, "namePrefix", 512) !== this.config.prefix) {
      throw new BrokerError("B2_PREFIX_SCOPE_INVALID", 503, false);
    }
    const buckets = arrayField(allowed, "buckets", "B2_AUTHORIZE_RESPONSE_INVALID");
    if (buckets.length !== 1) {
      throw new BrokerError("B2_BUCKET_SCOPE_INVALID", 503, false);
    }
    const bucket = providerObject(buckets[0], "B2_AUTHORIZE_RESPONSE_INVALID");
    if (
      stringField(bucket, "id", 64) !== this.config.bucketId ||
      stringField(bucket, "name", 128) !== this.config.bucketName
    ) {
      throw new BrokerError("B2_BUCKET_SCOPE_INVALID", 503, false);
    }
    const accountId = stringField(root, "accountId", 64);
    const apiUrl = providerBaseUrl(stringField(storage, "apiUrl", 512), "api");
    const downloadUrl = providerBaseUrl(stringField(storage, "downloadUrl", 512), "download");
    const authorizationProjection: JsonObject = {
      account_id: accountId,
      allowed: {
        bucket_id: this.config.bucketId,
        bucket_name: this.config.bucketName,
        capabilities: [...capabilities],
        name_prefix: this.config.prefix,
      },
      api_url_origin: apiUrl,
      application_key_expiration_timestamp: null,
      download_url_origin: downloadUrl,
      provider_api_version: "v4",
      raw_provider_response_retained: false,
      schema: "dpone.release-b2-authorization-projection.v1",
    };
    return {
      accountId,
      apiUrl,
      authorizationEvidence: {
        ...authorizationProjection,
        projection_sha256: await digestDomain(
          "dpone.release-b2-authorization-observation.v1",
          authorizationProjection,
        ),
      },
      authorizationToken: stringField(root, "authorizationToken", 2048),
      downloadUrl,
    };
  }
}

/** Native B2 writer whose key must have only the writeFiles capability. */
