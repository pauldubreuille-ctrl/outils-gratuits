
import { jwtVerify, createRemoteJWKSet } from "jose";

let cachedJWKS = null;
let cachedIssuer = null;

function getJWKS(teamDomain) {
  const issuer = teamDomain.replace(/\/+$/, "");

  if (!cachedJWKS || cachedIssuer !== issuer) {
    cachedIssuer = issuer;
    cachedJWKS = createRemoteJWKSet(
      new URL(`${issuer}/cdn-cgi/access/certs`)
    );
  }

  return { issuer, JWKS: cachedJWKS };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    const json = (data, status = 200) =>
      new Response(JSON.stringify(data), {
        status,
        headers: {
          "Content-Type": "application/json; charset=utf-8",
          "Cache-Control": "no-store"
        }
      });

    // Protection de toutes les routes API d'administration
    if (path === "/api/admin" || path.startsWith("/api/admin/")) {
      if (!env.POLICY_AUD || !env.TEAM_DOMAIN) {
        return json({ error: "Configuration de sécurité manquante" }, 500);
      }

      const token = request.headers.get("Cf-Access-Jwt-Assertion");

      if (!token) {
        return json({ error: "Authentification requise" }, 401);
      }

      try {
        const { issuer, JWKS } = getJWKS(env.TEAM_DOMAIN);

        await jwtVerify(token, JWKS, {
          issuer,
          audience: env.POLICY_AUD,
          algorithms: ["RS256"]
        });
      } catch {
        return json({ error: "Jeton Cloudflare Access invalide" }, 401);
      }

      // Liste des outils
      if (request.method === "GET" && path === "/api/admin/tools") {
        const result = await env.DB.prepare(
          "SELECT * FROM tools ORDER BY created_at DESC"
        ).all();

        return json(result.results);
      }

      // Création d'un outil
      if (request.method === "POST" && path === "/api/admin/tools") {
        let body;

        try {
          body = await request.json();
        } catch {
          return json({ error: "Données JSON invalides" }, 400);
        }

        const {
          slug,
          name,
          category,
          description = "",
          config = {}
        } = body;

        if (
          typeof slug !== "string" ||
          !/^[a-z0-9-]{2,80}$/.test(slug) ||
          typeof name !== "string" ||
          !name.trim() ||
          typeof category !== "string" ||
          !category.trim() ||
          typeof description !== "string" ||
          typeof config !== "object" ||
          config === null ||
          Array.isArray(config)
        ) {
          return json({ error: "Informations invalides" }, 400);
        }

        try {
          const result = await env.DB.prepare(
            `INSERT INTO tools
            (slug, name, category, description, config_json)
            VALUES (?, ?, ?, ?, ?)`
          ).bind(
            slug,
            name.trim(),
            category.trim(),
            description,
            JSON.stringify(config)
          ).run();

          return json({
            success: true,
            id: result.meta.last_row_id
          }, 201);
        } catch {
          return json({
            error: "Impossible de créer cet outil. Vérifie son identifiant."
          }, 409);
        }
      }

      // Modification ou désactivation d'un outil
      const match = path.match(/^\/api\/admin\/tools\/(\d+)$/);

      if (match) {
        const id = Number(match[1]);

        if (request.method === "PUT") {
          let body;

          try {
            body = await request.json();
          } catch {
            return json({ error: "Données JSON invalides" }, 400);
          }

          const {
            name,
            category,
            description = "",
            config = {},
            active = 1
          } = body;

          if (
            typeof name !== "string" ||
            !name.trim() ||
            typeof category !== "string" ||
            !category.trim() ||
            typeof description !== "string" ||
            typeof config !== "object" ||
            config === null ||
            Array.isArray(config) ||
            ![0, 1, false, true].includes(active)
          ) {
            return json({ error: "Informations invalides" }, 400);
          }

          const result = await env.DB.prepare(
            `UPDATE tools
             SET name = ?, category = ?, description = ?,
                 config_json = ?, active = ?,
                 updated_at = CURRENT_TIMESTAMP
             WHERE id = ?`
          ).bind(
            name.trim(),
            category.trim(),
            description,
            JSON.stringify(config),
            active ? 1 : 0,
            id
          ).run();

          return json({
            success: true,
            changes: result.meta.changes
          });
        }

        if (request.method === "DELETE") {
          const result = await env.DB.prepare(
            `UPDATE tools
             SET active = 0,
                 updated_at = CURRENT_TIMESTAMP
             WHERE id = ?`
          ).bind(id).run();

          return json({
            success: true,
            changes: result.meta.changes
          });
        }
      }

      return json({ error: "Route introuvable" }, 404);
    }

    // Le site public reste servi normalement
    return env.ASSETS.fetch(request);
  }
};
