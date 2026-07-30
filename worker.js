// =====================================================
// Cloudflare Worker — 파일 업로드 서비스
//
// 환경변수 (Workers > Settings > Variables):
//   UPLOAD_SECRET       : 업로드 비밀키
//   R2_PUBLIC_URL       : R2 퍼블릭 도메인 (https://pub-xxx.r2.dev)
//   R2_ACCOUNT_ID       : Cloudflare 계정 ID
//   R2_ACCESS_KEY_ID    : R2 API 토큰 Access Key
//   R2_SECRET_ACCESS_KEY: R2 API 토큰 Secret Key
//   R2_BUCKET_NAME      : R2 버킷 이름
//
// R2 바인딩 (Workers > Settings > Bindings > R2):
//   변수명: R2_BUCKET → file-upload 버킷
// =====================================================

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, X-Secret-Key',
};

// 20MB 이상인 파일은 멀티파트로 분할 업로드 (네트워크가 끊겨도 파트 단위로만 재시도)
const MULTIPART_PART_SIZE = 25 * 1024 * 1024;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    // GET /get-upload-url → presigned URL 발급 (R2 직접 업로드, 단일 PUT)
    if (url.pathname === '/get-upload-url' && request.method === 'GET') {
      return handleGetUploadUrl(request, env, url);
    }

    // POST /multipart-create → 멀티파트 업로드 시작
    if (url.pathname === '/multipart-create' && request.method === 'POST') {
      return handleMultipartCreate(request, env, url);
    }

    // GET /multipart-part-url → 멀티파트 파트별 presigned URL 발급
    if (url.pathname === '/multipart-part-url' && request.method === 'GET') {
      return handleMultipartPartUrl(request, env, url);
    }

    // POST /multipart-complete → 멀티파트 업로드 완료
    if (url.pathname === '/multipart-complete' && request.method === 'POST') {
      return handleMultipartComplete(request, env);
    }

    // POST /multipart-abort → 멀티파트 업로드 취소(정리)
    if (url.pathname === '/multipart-abort' && request.method === 'POST') {
      return handleMultipartAbort(request, env);
    }

    // POST /upload-raw → iOS 단축어용 직접 업로드
    if (url.pathname === '/upload-raw' && request.method === 'POST') {
      return handleRawUpload(request, env, url);
    }

    // POST /upload-base64 → iOS 단축어용 base64 업로드
    if (url.pathname === '/upload-base64' && request.method === 'POST') {
      return handleBase64Upload(request, env);
    }

    // POST /upload-file → 파일 업로드 (레거시, 소용량)
    if (url.pathname === '/upload-file' && request.method === 'POST') {
      return handleUpload(request, env);
    }

    // GET /upload-list → 파일 목록
    if (url.pathname === '/upload-list' && request.method === 'GET') {
      return handleList(request, env);
    }

    // DELETE /upload-delete → 파일 삭제
    if (url.pathname === '/upload-delete' && request.method === 'DELETE') {
      return handleDelete(request, env);
    }

    // GET /download → 파일 강제 다운로드
    if (url.pathname === '/download' && request.method === 'GET') {
      return handleDownload(request, env);
    }

    return new Response('Not found', { status: 404 });
  }
};

function checkSecret(request, env) {
  const key = request.headers.get('X-Secret-Key');
  if (key === env.UPLOAD_SECRET) return 'main';
  if (env.TEMP_SECRET && env.TEMP_EXPIRE && key === env.TEMP_SECRET) {
    const today = new Date().toISOString().slice(0, 10);
    if (today <= env.TEMP_EXPIRE) return 'temp';
  }
  if (env.DOWNLOAD_SECRET && key === env.DOWNLOAD_SECRET) return 'readonly';
  return false;
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders },
  });
}

function xmlTag(xml, tag) {
  const m = xml.match(new RegExp(`<${tag}>([^<]*)<\\/${tag}>`));
  return m ? m[1] : null;
}

// R2 오브젝트 키를 만들 때 쓰는 인코더. encodeURIComponent는 !*'() 를 인코딩하지 않고 그대로
// 두는데, AWS SigV4 서명 검증은 이 문자들도 퍼센트 인코딩되어 있어야 해서, 파일명에 괄호 등이
// 있으면 서명이 어긋나 SignatureDoesNotMatch가 난다. 그래서 그 문자들만 추가로 인코딩해준다.
function s3KeyEncode(str) {
  return encodeURIComponent(str).replace(/[!*'()]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase());
}

// ── AWS Signature V4 헬퍼
async function sha256hex(message) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(message));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}

async function hmac(key, msg) {
  const k = await crypto.subtle.importKey('raw', typeof key === 'string' ? new TextEncoder().encode(key) : key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return crypto.subtle.sign('HMAC', k, typeof msg === 'string' ? new TextEncoder().encode(msg) : msg);
}

async function hmacHex(key, msg) {
  return [...new Uint8Array(await hmac(key, msg))].map(b => b.toString(16).padStart(2, '0')).join('');
}

async function getSigningKey(secret, date, region, service) {
  const kDate = await hmac(`AWS4${secret}`, date);
  const kRegion = await hmac(kDate, region);
  const kService = await hmac(kRegion, service);
  return hmac(kService, 'aws4_request');
}

// 브라우저가 직접 R2로 PUT할 수 있는 presigned URL 생성 (단일 PUT / 멀티파트 파트 공용)
async function generatePresignedUrl(env, key, contentType, expiresIn = 3600, extraParams = {}) {
  const accountId = env.R2_ACCOUNT_ID;
  const accessKeyId = env.R2_ACCESS_KEY_ID;
  const secretKey = env.R2_SECRET_ACCESS_KEY;
  const bucket = env.R2_BUCKET_NAME;
  const region = 'auto';
  const host = `${accountId}.r2.cloudflarestorage.com`;

  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '').slice(0, 15) + 'Z';
  const dateStamp = amzDate.slice(0, 8);
  const credentialScope = `${dateStamp}/${region}/s3/aws4_request`;

  const params = new URLSearchParams({
    'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
    'X-Amz-Credential': `${accessKeyId}/${credentialScope}`,
    'X-Amz-Date': amzDate,
    'X-Amz-Expires': String(expiresIn),
    'X-Amz-SignedHeaders': 'host',
  });
  for (const [k, v] of Object.entries(extraParams)) params.set(k, v);

  const sortedParams = [...params.entries()].sort(([a], [b]) => a.localeCompare(b));
  const canonicalQS = sortedParams.map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&');
  const canonicalUri = `/${bucket}/${key}`;
  const canonicalHeaders = `host:${host}\n`;
  const canonicalReq = ['PUT', canonicalUri, canonicalQS, canonicalHeaders, 'host', 'UNSIGNED-PAYLOAD'].join('\n');
  const stringToSign = ['AWS4-HMAC-SHA256', amzDate, credentialScope, await sha256hex(canonicalReq)].join('\n');
  const signingKey = await getSigningKey(secretKey, dateStamp, region, 's3');
  const signature = await hmacHex(signingKey, stringToSign);

  params.set('X-Amz-Signature', signature);
  return `https://${host}${canonicalUri}?${params.toString()}`;
}

// Worker가 R2에 서버사이드로 직접 보내는 서명된 요청 (멀티파트 생성/조회/완료/취소용)
async function r2SignedRequest(env, method, key, queryParams, body) {
  const accountId = env.R2_ACCOUNT_ID;
  const accessKeyId = env.R2_ACCESS_KEY_ID;
  const secretKey = env.R2_SECRET_ACCESS_KEY;
  const bucket = env.R2_BUCKET_NAME;
  const region = 'auto';
  const host = `${accountId}.r2.cloudflarestorage.com`;

  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '').slice(0, 15) + 'Z';
  const dateStamp = amzDate.slice(0, 8);
  const credentialScope = `${dateStamp}/${region}/s3/aws4_request`;

  const payloadHash = await sha256hex(body || '');

  const sortedParams = Object.entries(queryParams || {}).sort(([a], [b]) => a.localeCompare(b));
  const canonicalQS = sortedParams.map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&');
  const canonicalUri = `/${bucket}/${key}`;
  const canonicalHeaders = `host:${host}\nx-amz-content-sha256:${payloadHash}\nx-amz-date:${amzDate}\n`;
  const signedHeaders = 'host;x-amz-content-sha256;x-amz-date';
  const canonicalReq = [method, canonicalUri, canonicalQS, canonicalHeaders, signedHeaders, payloadHash].join('\n');
  const stringToSign = ['AWS4-HMAC-SHA256', amzDate, credentialScope, await sha256hex(canonicalReq)].join('\n');
  const signingKey = await getSigningKey(secretKey, dateStamp, region, 's3');
  const signature = await hmacHex(signingKey, stringToSign);

  const authHeader = `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
  const reqUrl = `https://${host}${canonicalUri}${canonicalQS ? '?' + canonicalQS : ''}`;

  return fetch(reqUrl, {
    method,
    headers: {
      'Authorization': authHeader,
      'x-amz-date': amzDate,
      'x-amz-content-sha256': payloadHash,
      ...(body ? { 'Content-Type': 'application/xml' } : {}),
    },
    body: body || undefined,
  });
}

// ── Presigned URL 발급 (단일 PUT, 소용량용)
async function handleGetUploadUrl(request, env, url) {
  const keyType = checkSecret(request, env);
  if (!keyType || keyType === 'readonly') {
    return json({ error: '업로드 권한이 없습니다.' }, 403);
  }

  try {
    const filename = url.searchParams.get('filename') || `file_${Date.now()}`;
    const contentType = 'application/octet-stream';
    const date = new Date().toISOString().slice(0, 10);
    const key = `uploads/${keyType}/${date}/${s3KeyEncode(filename)}`;

    const uploadUrl = await generatePresignedUrl(env, key, contentType);
    return json({ uploadUrl, key, downloadUrl: `${env.R2_PUBLIC_URL}/${key}` });
  } catch (e) {
    return json({ error: e.message }, 500);
  }
}

// ── 멀티파트 업로드 시작
async function handleMultipartCreate(request, env, url) {
  const keyType = checkSecret(request, env);
  if (!keyType || keyType === 'readonly') return json({ error: '업로드 권한이 없습니다.' }, 403);

  try {
    const filename = url.searchParams.get('filename') || `file_${Date.now()}`;
    const contentType = url.searchParams.get('type') || 'application/octet-stream';
    const date = new Date().toISOString().slice(0, 10);
    const key = `uploads/${keyType}/${date}/${s3KeyEncode(filename)}`;

    const res = await r2SignedRequest(env, 'POST', key, { uploads: '' }, null);
    const bodyText = await res.text();
    if (!res.ok) return json({ error: `멀티파트 시작 실패: ${bodyText.slice(0, 200)}` }, 500);

    const uploadId = xmlTag(bodyText, 'UploadId');
    if (!uploadId) return json({ error: '업로드 ID를 받지 못했습니다.' }, 500);

    return json({ key, uploadId, partSize: MULTIPART_PART_SIZE });
  } catch (e) {
    return json({ error: e.message }, 500);
  }
}

// ── 멀티파트 파트별 presigned URL 발급
async function handleMultipartPartUrl(request, env, url) {
  const keyType = checkSecret(request, env);
  if (!keyType || keyType === 'readonly') return json({ error: '업로드 권한이 없습니다.' }, 403);

  try {
    const key = url.searchParams.get('key');
    const uploadId = url.searchParams.get('uploadId');
    const partNumber = url.searchParams.get('partNumber');
    if (!key || !uploadId || !partNumber) return json({ error: '파라미터가 부족합니다.' }, 400);
    if (!key.startsWith(`uploads/${keyType}/`)) return json({ error: '잘못된 경로입니다.' }, 400);

    const uploadUrl = await generatePresignedUrl(env, key, 'application/octet-stream', 3600, {
      partNumber, uploadId,
    });
    return json({ uploadUrl });
  } catch (e) {
    return json({ error: e.message }, 500);
  }
}

// ── 멀티파트 업로드 완료 (R2에서 파트 목록을 직접 조회해서 완료 처리 — 브라우저가 ETag를 몰라도 됨)
async function handleMultipartComplete(request, env) {
  const keyType = checkSecret(request, env);
  if (!keyType || keyType === 'readonly') return json({ error: '업로드 권한이 없습니다.' }, 403);

  try {
    const { key, uploadId } = await request.json();
    if (!key || !uploadId) return json({ error: '파라미터가 부족합니다.' }, 400);
    if (!key.startsWith(`uploads/${keyType}/`)) return json({ error: '잘못된 경로입니다.' }, 400);

    const parts = [];
    let marker = '';
    while (true) {
      const q = { uploadId, 'max-parts': '1000' };
      if (marker) q['part-number-marker'] = marker;
      const res = await r2SignedRequest(env, 'GET', key, q, null);
      const bodyText = await res.text();
      if (!res.ok) return json({ error: `파트 조회 실패: ${bodyText.slice(0, 200)}` }, 500);

      const partMatches = [...bodyText.matchAll(/<Part>([\s\S]*?)<\/Part>/g)];
      for (const m of partMatches) {
        const partNumber = xmlTag(m[1], 'PartNumber');
        const etag = xmlTag(m[1], 'ETag');
        parts.push({ partNumber: Number(partNumber), etag });
      }

      const isTruncated = xmlTag(bodyText, 'IsTruncated') === 'true';
      if (!isTruncated) break;
      marker = xmlTag(bodyText, 'NextPartNumberMarker');
    }

    if (!parts.length) return json({ error: '업로드된 파트가 없습니다.' }, 400);
    parts.sort((a, b) => a.partNumber - b.partNumber);

    const completeXml = `<CompleteMultipartUpload>${parts.map(p => `<Part><PartNumber>${p.partNumber}</PartNumber><ETag>${p.etag}</ETag></Part>`).join('')}</CompleteMultipartUpload>`;

    const completeRes = await r2SignedRequest(env, 'POST', key, { uploadId }, completeXml);
    const completeBody = await completeRes.text();
    if (!completeRes.ok) return json({ error: `업로드 완료 실패: ${completeBody.slice(0, 200)}` }, 500);

    return json({ downloadUrl: `${env.R2_PUBLIC_URL}/${key}`, key });
  } catch (e) {
    return json({ error: e.message }, 500);
  }
}

// ── 멀티파트 업로드 취소 (실패 시 정리용 — 안 지우면 미완성 파트도 용량을 차지함)
async function handleMultipartAbort(request, env) {
  const keyType = checkSecret(request, env);
  if (!keyType || keyType === 'readonly') return json({ error: '권한이 없습니다.' }, 403);

  try {
    const { key, uploadId } = await request.json();
    if (!key || !uploadId) return json({ error: '파라미터가 부족합니다.' }, 400);
    if (!key.startsWith(`uploads/${keyType}/`)) return json({ error: '잘못된 경로입니다.' }, 400);

    await r2SignedRequest(env, 'DELETE', key, { uploadId }, null);
    return json({ success: true });
  } catch (e) {
    return json({ error: e.message }, 500);
  }
}

// ── iOS 단축어용 직접 업로드
async function handleRawUpload(request, env, url) {
  const keyType = checkSecret(request, env);
  if (!keyType) return json({ error: '비밀키가 올바르지 않습니다.' }, 401);

  try {
    const now = new Date();
    const ts = now.toISOString().replace(/[-:T]/g, '').slice(0, 15);
    const originalName = url.searchParams.get('filename') || `file_${ts}`;
    const ext = originalName.includes('.') ? '' : '.jpg';
    const filename = originalName.includes('.') ? originalName : `${originalName}${ext}`;
    const uniqueName = `${ts}_${filename}`;
    const contentType = request.headers.get('Content-Type') || 'application/octet-stream';
    const date = new Date().toISOString().slice(0, 10);
    const key = `uploads/${keyType}/${date}/${s3KeyEncode(uniqueName)}`;

    await env.R2_BUCKET.put(key, request.body, {
      httpMetadata: { contentType },
    });

    return json({ downloadUrl: `${env.R2_PUBLIC_URL}/${key}`, key });
  } catch (e) {
    return json({ error: e.message }, 500);
  }
}

// ── iOS 단축어용 base64 업로드
async function handleBase64Upload(request, env) {
  const keyType = checkSecret(request, env);
  if (!keyType) return json({ error: '비밀키가 올바르지 않습니다.' }, 401);

  try {
    const { filename, contentType, data } = await request.json();
    if (!data || !filename) return json({ error: '파일 데이터가 없습니다.' }, 400);

    const clean = data.replace(/\s/g, '');
    const binary = atob(clean);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);

    const date = new Date().toISOString().slice(0, 10);
    const key = `uploads/${keyType}/${date}/${s3KeyEncode(filename)}`;

    await env.R2_BUCKET.put(key, bytes, {
      httpMetadata: { contentType: contentType || 'application/octet-stream' },
    });

    return json({ downloadUrl: `${env.R2_PUBLIC_URL}/${key}`, key });
  } catch (e) {
    return json({ error: e.message }, 500);
  }
}

// ── 파일 업로드 (레거시 - 소용량용)
async function handleUpload(request, env) {
  const keyType = checkSecret(request, env);
  if (!keyType || keyType === 'readonly') {
    return json({ error: '업로드 권한이 없습니다.' }, 403);
  }
  try {
    const formData = await request.formData();
    const file = formData.get('file');
    if (!file) return json({ error: '파일이 없습니다.' }, 400);

    const MAX_FILE = 100 * 1024 * 1024; // Worker 경유는 100MB 제한
    if (file.size > MAX_FILE) return json({ error: 'Worker 경유 업로드는 100MB 제한입니다. presigned URL을 사용하세요.' }, 400);

    const date = new Date().toISOString().slice(0, 10);
    const key = `uploads/${keyType}/${date}/${s3KeyEncode(file.name)}`;

    await env.R2_BUCKET.put(key, file.stream(), {
      httpMetadata: { contentType: file.type || 'application/octet-stream' },
    });

    return json({ downloadUrl: `${env.R2_PUBLIC_URL}/${key}`, key });
  } catch (e) {
    return json({ error: e.message }, 500);
  }
}

// ── 파일 목록
async function handleList(request, env) {
  const keyType = checkSecret(request, env);
  if (!keyType) {
    return json({ error: '비밀키가 올바르지 않습니다.' }, 401);
  }

  // readonly 키는 오늘 날짜 파일만 조회
  if (keyType === 'readonly') {
    const today = new Date().toISOString().slice(0, 10);
    const [listedMain, listedTemp] = await Promise.all([
      env.R2_BUCKET.list({ prefix: `uploads/main/${today}/` }),
      env.R2_BUCKET.list({ prefix: `uploads/temp/${today}/` }),
    ]);
    const files = [...listedMain.objects, ...listedTemp.objects].map(obj => ({
      key: obj.key, size: obj.size, uploaded: obj.uploaded,
      url: `${env.R2_PUBLIC_URL}/${obj.key}`,
    }));
    files.sort((a, b) => new Date(b.uploaded) - new Date(a.uploaded));
    return json({ files });
  }

  const [listed, listedLegacy] = await Promise.all([
    env.R2_BUCKET.list({ prefix: `uploads/${keyType}/` }),
    keyType === 'main' ? env.R2_BUCKET.list({ prefix: 'uploads/' }) : Promise.resolve({ objects: [] }),
  ]);

  const legacyFiles = listedLegacy.objects.filter(obj =>
    !obj.key.startsWith('uploads/main/') && !obj.key.startsWith('uploads/temp/')
  );

  const allFiles = [...listed.objects, ...legacyFiles];
  const files = allFiles.map(obj => ({
    key: obj.key, size: obj.size, uploaded: obj.uploaded,
    url: `${env.R2_PUBLIC_URL}/${obj.key}`,
  }));

  files.sort((a, b) => new Date(b.uploaded) - new Date(a.uploaded));
  return json({ files });
}

// ── 파일 삭제
async function handleDelete(request, env) {
  const keyType = checkSecret(request, env);
  if (!keyType || keyType === 'readonly') {
    return json({ error: '삭제 권한이 없습니다.' }, 403);
  }
  try {
    const { key } = await request.json();
    if (!key || !key.startsWith('uploads/')) return json({ error: '잘못된 경로입니다.' }, 400);
    await env.R2_BUCKET.delete(key);
    return json({ success: true });
  } catch (e) {
    return json({ error: e.message }, 500);
  }
}

// ── 파일 강제 다운로드
async function handleDownload(request, env) {
  const keyType = checkSecret(request, env);
  if (!keyType) {
    return json({ error: '비밀키가 올바르지 않습니다.' }, 401);
  }
  try {
    const url = new URL(request.url);
    const key = url.searchParams.get('key');
    if (!key || !key.startsWith('uploads/')) return json({ error: '잘못된 경로입니다.' }, 400);

    const object = await env.R2_BUCKET.get(key);
    if (!object) return json({ error: '파일을 찾을 수 없습니다.' }, 404);

    const filename = decodeURIComponent(key.split('/').pop());
    return new Response(object.body, {
      headers: {
        'Content-Type': object.httpMetadata?.contentType || 'application/octet-stream',
        'Content-Disposition': `attachment; filename*=UTF-8''${encodeURIComponent(filename)}`,
        ...corsHeaders,
      },
    });
  } catch (e) {
    return json({ error: e.message }, 500);
  }
}
