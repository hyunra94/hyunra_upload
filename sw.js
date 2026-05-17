const CACHE_NAME = 'share-target-v1';

// 공유된 파일을 캐시에 저장하고 메인 페이지로 리다이렉트
self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);

  if (url.pathname === '/share-target' && event.request.method === 'POST') {
    event.respondWith(handleShareTarget(event.request));
    return;
  }
});

async function handleShareTarget(request) {
  try {
    const formData = await request.formData();
    const files = formData.getAll('file');

    if (files.length > 0) {
      // 파일 데이터를 캐시에 저장
      const fileDataList = await Promise.all(
        files.map(async file => {
          const buffer = await file.arrayBuffer();
          return {
            name: file.name,
            type: file.type,
            size: file.size,
            data: Array.from(new Uint8Array(buffer)),
          };
        })
      );

      const cache = await caches.open(CACHE_NAME);
      await cache.put(
        '/shared-files',
        new Response(JSON.stringify(fileDataList), {
          headers: { 'Content-Type': 'application/json' },
        })
      );
    }
  } catch (e) {
    console.error('Share target error:', e);
  }

  // 메인 페이지로 리다이렉트
  return Response.redirect('/?shared=true', 303);
}
