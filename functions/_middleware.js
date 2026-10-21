function deny() {
  return new Response("Acceso restringido. Ingresá tus credenciales.", {
    status: 401,
    headers: {
      "WWW-Authenticate": 'Basic realm="RC Red de Servicios", charset="UTF-8"',
      "Cache-Control": "no-store",
      "Content-Type": "text/plain; charset=UTF-8"
    }
  });
}

export async function onRequest({ request, env, next }) {
  if (!env.APP_USER || !env.APP_PASSWORD) {
    return new Response("La autenticación no está configurada.", {
      status: 503,
      headers: { "Cache-Control": "no-store" }
    });
  }

  const auth = request.headers.get("Authorization") || "";

  if (!auth.startsWith("Basic ")) {
    return deny();
  }

  let decoded;

  try {
    decoded = atob(auth.slice(6));
  } catch {
    return deny();
  }

  const separator = decoded.indexOf(":");

  if (separator < 0) {
    return deny();
  }

  const username = decoded.slice(0, separator);
  const password = decoded.slice(separator + 1);

  if (
    username !== env.APP_USER ||
    password !== env.APP_PASSWORD
  ) {
    return deny();
  }

  const response = await next();
  const headers = new Headers(response.headers);
  headers.set("Cache-Control", "private, no-store");

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
}
