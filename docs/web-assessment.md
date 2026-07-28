# Website and web-application assessment

Passive checks use only the configured small path set, bounded GET requests,
verified TLS metadata, response headers, cookies, OpenAPI, and error metadata.
Standard adds fixed OPTIONS and synthetic malformed/missing/unexpected/reflected
inputs. It does not crawl, submit forms automatically, authenticate by guessing,
upload files, delete data, or follow an out-of-scope redirect.

Responses are streamed with a byte cap. Redirect destinations are revalidated
and are not silently followed. A 401/403 is protected coverage. Missing
headers, permissive CORS, reflection, and detailed error markers are reported
with explicit confidence; reflection alone is informational.

```bash
redteam assess web http://127.0.0.1:8000 --profile passive \
  --authorization "I own this local web application and authorize bounded testing."
```
