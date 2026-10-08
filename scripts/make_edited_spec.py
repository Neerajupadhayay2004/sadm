"""Create the edited VAmPI spec used for testing (original file is never modified).

Edits (spec vs. real API deliberately diverge):
  - remove GET /users/v1/_debug  -> live route, undocumented  -> SHADOW
  - remove GET /createdb         -> live route, undocumented  -> SHADOW
  - GET /users/v1 deprecated     -> still called              -> ZOMBIE
  - PUT .../password, DELETE /users/v1/{username} stay documented but are never called -> ORPHAN
  - servers url points at the local gateway
"""
import sys
import yaml

src, dst = sys.argv[1:3]
spec = yaml.safe_load(open(src, encoding="utf-8"))
for path in ("/users/v1/_debug", "/createdb"):
    spec["paths"].pop(path)
spec["paths"]["/users/v1"]["get"]["deprecated"] = True
spec["servers"] = [{"url": "http://localhost:8080"}]
yaml.safe_dump(spec, open(dst, "w", encoding="utf-8"), sort_keys=False)
