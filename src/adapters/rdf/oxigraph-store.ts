/**
 * Oxigraph RDF Store Adapter — Milestone 4
 *
 * Single class implementing both RDFIndex and SPARQLEngine.
 * Oxigraph's Store is both an index and a query engine,
 * so there is no need for separate classes.
 *
 * JSON-LD → N-Quads conversion via the jsonld library,
 * because Oxigraph WASM does not parse JSON-LD directly.
 *
 * Remote context fetches are explicitly blocked.
 */

import oxigraph from "oxigraph";
import type { Term } from "oxigraph";
import jsonld from "jsonld";
import type {
  RDFIndex,
  SPARQLEngine,
  QueryResult,
  RDFTerm,
} from "../../kernel/types.js";

export class OxigraphRDFStore implements RDFIndex, SPARQLEngine {
  private store: oxigraph.Store;

  constructor() {
    this.store = new oxigraph.Store();
  }

  async load(
    content: Uint8Array,
    format: string,
    baseURI: string,
  ): Promise<void> {
    const text = new TextDecoder().decode(content);

    if (format === "application/ld+json") {
      const doc = JSON.parse(text);
      const nquads = (await jsonld.toRDF(doc, {
        format: "application/n-quads",
        documentLoader: (url: string) => {
          throw new Error(`Remote context fetch blocked: ${url}`);
        },
      })) as string;
      this.store.load(nquads, { format: "application/n-quads", lenient: true });
    } else {
      this.store.load(text, {
        format,
        base_iri: baseURI || undefined,
        lenient: true,
      });
    }
  }

  tripleCount(): number {
    return this.store.size;
  }

  async query(sparql: string, _index: RDFIndex): Promise<QueryResult> {
    const results = this.store.query(sparql);

    // SELECT queries return Map<string, Term>[]
    if (!Array.isArray(results)) {
      // ASK query returns boolean — wrap as empty bindings
      return { bindings: [], truncated: false };
    }

    const bindings: Array<Record<string, RDFTerm>> = [];

    for (const row of results) {
      if (!(row instanceof Map)) continue; // skip CONSTRUCT quads
      const binding: Record<string, RDFTerm> = {};
      for (const [key, term] of row.entries()) {
        binding[key] = mapOxigraphTerm(term);
      }
      bindings.push(binding);
    }

    return { bindings, truncated: false };
  }
}

function mapOxigraphTerm(term: Term): RDFTerm {
  switch (term.termType) {
    case "NamedNode":
      return { type: "uri", value: term.value };
    case "Literal":
      return {
        type: "literal",
        value: term.value,
        ...(term.datatype &&
          term.datatype.value !==
            "http://www.w3.org/2001/XMLSchema#string" && {
            datatype: term.datatype.value,
          }),
        ...(term.language && { language: term.language }),
      };
    case "BlankNode":
      return { type: "bnode", value: term.value };
    default:
      return { type: "uri", value: term.value };
  }
}
