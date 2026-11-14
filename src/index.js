
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    const json = (data, status = 200) =>
      new Response(JSON.stringify(data), {
        status,
        headers: { "Content-Type": "application/json; charset=utf-8" }
      });

    // Les routes d'administration doivent être protégées
    // par une application Cloudflare Access.
    if (path.startsWith("/api/admin/")) {
      if (!request.headers.get("Cf-Access-Jwt-Assertion")) {
        return json({ error: "Accès refusé" }, 401);
      }

      if (request.method === "GET" && path === "/api/admin/tools") {
        const result = await env.DB.prepare(
          "SELECT * FROM tools ORDER BY created_at DESC"
        ).all();

        return json(result.results);
      }

      if (request.method === "POST" && path === "/api/admin/tools") {
        let body;

        try {
          body = await request.json();
        } catch {
          return json({ error: "Données JSON invalides" }, 400);
        }

        const { slug, name, category, description = "", config = {} } = body;

        if (
          typeof slug !== "string" ||
          !/^[a-z0-9-]{2,80}$/.test(slug) ||
          typeof name !== "string" ||
          !name.trim() ||
          typeof category !== "string" ||
          !category.trim() ||
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
            String(description),
            JSON.stringify(config)
          ).run();

          return json({ success: true, id: result.meta.last_row_id }, 201);
        } catch {
          return json({ error: "Impossible de créer cet outil. Vérifie son identifiant." }, 409);
        }
      }

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

          const { name, category, description = "", config = {}, active = 1 } = body;

          if (
            typeof name !== "string" ||
            !name.trim() ||
            typeof category !== "string" ||
            !category.trim() ||
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
            String(description),
            JSON.stringify(config),
            active ? 1 : 0,
            id
          ).run();

          return json({ success: true, changes: result.meta.changes });
        }

        if (request.method === "DELETE") {
          const result = await env.DB.prepare(
            `UPDATE tools SET active = 0,
             updated_at = CURRENT_TIMESTAMP WHERE id = ?`
          ).bind(id).run();

          return json({ success: true, changes: result.meta.changes });
        }
      }

      return json({ error: "Route introuvable" }, 404);
    }

    // Le site public continue d'être servi depuis les fichiers statiques.
    return env.ASSETS.fetch(request);
  }
};
