export interface CloudBucketResult {
  url: string;
  provider: string;
  exposed: boolean;
  listable: boolean;
}

const CHECK_TIMEOUT = 8000;

export async function checkCloudBuckets(orgDomain: string): Promise<CloudBucketResult[]> {
  // Generate bucket name guesses from the domain
  const baseName = orgDomain.replace(/\.(com|org|net|io|co|dev)$/i, "").replace(/\./g, "-");

  const bucketGuesses = [
    baseName,
    `${baseName}-assets`,
    `${baseName}-public`,
    `${baseName}-backup`,
    `${baseName}-data`,
  ];

  const results: CloudBucketResult[] = [];

  // Check S3 buckets
  const s3Checks = bucketGuesses.map((name) => checkS3Bucket(name));
  // Check Azure blob storage
  const azureChecks = bucketGuesses.slice(0, 3).map((name) => checkAzureBlob(name));
  // Check GCS buckets
  const gcsChecks = bucketGuesses.slice(0, 3).map((name) => checkGCSBucket(name));

  const allResults = await Promise.allSettled([...s3Checks, ...azureChecks, ...gcsChecks]);

  for (const result of allResults) {
    if (result.status === "fulfilled" && result.value.exposed) {
      results.push(result.value);
    }
  }

  return results;
}

async function checkS3Bucket(name: string): Promise<CloudBucketResult> {
  const url = `https://${name}.s3.amazonaws.com`;
  const result: CloudBucketResult = { url, provider: "AWS S3", exposed: false, listable: false };

  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(CHECK_TIMEOUT) });

    if (res.status === 200) {
      const body = await res.text();
      result.exposed = true;
      // S3 returns XML with ListBucketResult if listable
      result.listable = body.includes("ListBucketResult");
    } else if (res.status === 403) {
      // Bucket exists but not public — not exposed
      result.exposed = false;
    }
  } catch {
    // Bucket doesn't exist or unreachable
  }

  return result;
}

async function checkAzureBlob(name: string): Promise<CloudBucketResult> {
  const url = `https://${name}.blob.core.windows.net`;
  const result: CloudBucketResult = { url, provider: "Azure Blob", exposed: false, listable: false };

  try {
    const res = await fetch(`${url}?comp=list&restype=container`, {
      signal: AbortSignal.timeout(CHECK_TIMEOUT),
    });

    if (res.status === 200) {
      const body = await res.text();
      result.exposed = true;
      result.listable = body.includes("EnumerationResults");
    }
  } catch {
    // Doesn't exist
  }

  return result;
}

async function checkGCSBucket(name: string): Promise<CloudBucketResult> {
  const url = `https://storage.googleapis.com/${name}`;
  const result: CloudBucketResult = { url, provider: "Google Cloud Storage", exposed: false, listable: false };

  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(CHECK_TIMEOUT) });

    if (res.status === 200) {
      const body = await res.text();
      result.exposed = true;
      result.listable = body.includes("ListBucketResult");
    }
  } catch {
    // Doesn't exist
  }

  return result;
}
