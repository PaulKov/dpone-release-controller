export const PUBLICATION_REVIEW_TEMPLATE_HEADER =
  "// PUBLICATION REVIEW TEMPLATE: provider identifiers are synthetic and cannot authorize deployment.";

/** Parse JSON plus trailing commas and the one exact publication-template header. */
export function parseReviewedJsonc(source, path) {
  const body = source.startsWith(`${PUBLICATION_REVIEW_TEMPLATE_HEADER}\n`)
    ? source.slice(PUBLICATION_REVIEW_TEMPLATE_HEADER.length + 1)
    : source;
  let result = "";
  let inString = false;
  let escaped = false;
  for (let index = 0; index < body.length; index += 1) {
    const character = body[index];
    if (character === undefined) break;
    if (inString) {
      result += character;
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === '"') inString = false;
      continue;
    }
    if (character === '"') {
      inString = true;
      result += character;
      continue;
    }
    if (character === "/" && (body[index + 1] === "/" || body[index + 1] === "*")) {
      throw new Error(`comments are forbidden in reviewed Worker config: ${path}`);
    }
    if (character === ",") {
      let lookahead = index + 1;
      while (/\s/u.test(body[lookahead] ?? "")) lookahead += 1;
      if (body[lookahead] === "}" || body[lookahead] === "]") continue;
    }
    result += character;
  }
  if (inString || escaped) throw new Error(`invalid reviewed Worker config: ${path}`);
  return JSON.parse(result);
}
