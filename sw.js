const CACHE_NAME = 'share-target-v1';
const SHARED_PREFIX = 'shared-files/';

// 새 버전이 바로 적용되도록 (대기 상태로 남으면 공유 시 구버전 SW가 처리함)
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', event => event.waitUntil(self.clients.claim()));

// 공유된 파일을 캐시에 저장하고 메인 페이지로 리다이렉트
self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);

  if (url.pathname.endsWith('/share-target') && event.request.method === 'POST') {
    event.respondWith(handleShareTarget(event.request));
    return;
  }
});

async function handleShareTarget(request) {
  const scopeUrl = new URL(self.registration.scope);
  let count = 0, err = '';
  try {
    const formData = await request.formData();
    const files = formData.getAll('file').filter(f => f instanceof File);
    count = files.length;
    if (!count) err = `받은 파일 없음 (필드: ${[...formData.keys()].join(",") || "없음"}, 형식: ${(request.headers.get("content-type") || "없음").split(";")[0]})`;

    const cache = await caches.open(CACHE_NAME);
    // 이전 공유 잔여물 정리
    for (const req of await cache.keys()) await cache.delete(req);

    // 파일을 JSON 숫자 배열로 변환하면 사진 몇 장만으로도 메모리가 수십~수백 MB로 불어나
    // 실패하므로, Blob 그대로 파일별 Response로 저장한다.
    const stamp = Date.now();
    await Promise.all(files.map((file, i) =>
      cache.put(
        new URL(`${SHARED_PREFIX}${stamp}-${i}`, scopeUrl).href,
        new Response(file, {
          headers: {
            'Content-Type': file.type || 'application/octet-stream',
            'X-File-Name': encodeURIComponent(file.name || `shared-${stamp}-${i}`),
          },
        })
      )
    ));
  } catch (e) {
    console.error('Share target error:', e);
    err = String((e && e.message) || e);
  }

  // 메인 페이지로 리다이렉트 (서브경로 배포 대응: 등록 scope 기준 상대 경로 사용)
  // 처리 결과를 쿼리로 넘겨 페이지에서 표시 (진단용)
  const q = new URLSearchParams({ shared: String(count) });
  if (err) q.set('share_err', err.slice(0, 200));
  return Response.redirect(`${scopeUrl.pathname}?${q}`, 303);
}
