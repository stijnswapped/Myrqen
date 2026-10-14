import test from "node:test";
import assert from "node:assert/strict";
import { parsePython } from "../dist/index.js";

test("parses modern Python without error nodes", () => {
  const { module, errors } = parsePython(`
from fastapi import APIRouter
router = APIRouter(prefix="/x")

@router.get("/{item_id}")
async def read(item_id: int, q: str | None = None) -> dict:
    match q:
        case "a":
            pass
    if (n := len(q or "")) > 3:
        return {"n": n, **{}}
    return {"q": f"{q!r:>3}"}
`);
  assert.equal(errors, 0);
  const fn = module.body.find((stmt) => stmt.k === "funcdef");
  assert.equal(fn.name, "read");
  assert.equal(fn.decorators.length, 1);
  assert.equal(fn.params.map((p) => p.name).join(","), "item_id,q");
  assert.equal(fn.isAsync, true);
});

test("f-strings keep their literal text and their replacement expressions", () => {
  const { module } = parsePython(`x = f"SELECT * FROM t WHERE a = '{value}' AND b = {{literal}}"\n`);
  const assign = module.body[0];
  assert.equal(assign.value.k, "fstr");
  const literal = assign.value.parts.filter((part) => typeof part === "string").join("");
  assert.match(literal, /SELECT \* FROM t WHERE a = ''/);
  assert.match(literal, /\{literal\}/);
  assert.equal(assign.value.parts.filter((part) => typeof part !== "string")[0].id, "value");
});

test("decorators with dotted names become attribute calls", () => {
  const { module } = parsePython(`@bp.route("/a/<int:id>", methods=["POST"])\ndef view(id):\n    return ""\n`);
  const decorator = module.body[0].decorators[0].expr;
  assert.equal(decorator.k, "call");
  assert.equal(decorator.func.k, "attr");
  assert.equal(decorator.func.attr, "route");
  assert.equal(decorator.kwargs[0].name, "methods");
});

test("`not` binds tighter than `and`/`or`, as in Python", () => {
  const { module } = parsePython(`if not a or not b and c:\n    pass\nif not (a or b):\n    pass\n`);
  const first = module.body[0].branches[0].test;
  assert.equal(first.k, "boolop");
  assert.equal(first.op, "or");
  assert.equal(first.left.k, "not");
  assert.equal(first.left.operand.id, "a");
  const second = module.body[1].branches[0].test;
  assert.equal(second.k, "not");
  assert.equal(second.operand.k, "boolop");
});

test("a damaged file still yields the statements around the damage", () => {
  const { module, errors } = parsePython(`def ok():\n    return 1\n\ndef broken(:\n    pass\n\ndef also_ok():\n    return 2\n`);
  assert.ok(errors > 0);
  const names = module.body.filter((stmt) => stmt.k === "funcdef").map((fn) => fn.name);
  assert.ok(names.includes("ok"));
  assert.ok(names.includes("also_ok"));
});
