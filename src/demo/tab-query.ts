/**
 * Tab C: Storeless Oracle — Query Console
 *
 * Load verified content into an in-memory RDF graph (Oxigraph WASM)
 * and query it with SPARQL. Includes the Entailment Boundary Demonstrator.
 *
 * Kernel functions used:
 *   buildGraph, resolveEntailmentMode, executeQuery, OxigraphRDFStore, stableStringify
 */

import { buildGraph, resolveEntailmentMode } from "../kernel/graph-builder.js";
import { executeQuery } from "../kernel/query-executor.js";
import { OxigraphRDFStore } from "../adapters/rdf/oxigraph-store.js";
import { stableStringify } from "../kernel/canonicalize.js";
import { demoState } from "./state.js";

let container: HTMLElement;
let store: OxigraphRDFStore | null = null;

// Entailment trap fixture (inline)
const ENTAILMENT_TRAP = {
  "@context": {
    "schema": "http://schema.org/",
    "rdfs": "http://www.w3.org/2000/01/rdf-schema#",
    "ex": "http://example.org/",
  },
  "@graph": [
    {
      "@id": "ex:SoftwareArchitect",
      "@type": "rdfs:Class",
      "rdfs:subClassOf": { "@id": "schema:Person" },
    },
    {
      "@id": "ex:testSubject",
      "@type": "ex:SoftwareArchitect",
      "schema:name": "Ada Lovelace",
    },
  ],
};

const EXAMPLE_QUERIES = [
  {
    label: "All names",
    sparql: `SELECT ?name WHERE { ?s <http://schema.org/name> ?name }`,
  },
  {
    label: "All job titles",
    sparql: `SELECT ?title WHERE { ?s <http://schema.org/jobTitle> ?title }`,
  },
  {
    label: "All triples",
    sparql: `SELECT ?s ?p ?o WHERE { ?s ?p ?o } LIMIT 50`,
  },
  {
    label: "Entailment: schema:Person",
    sparql: `SELECT ?s WHERE { ?s a <http://schema.org/Person> }`,
  },
  {
    label: "Entailment: ex:SoftwareArchitect",
    sparql: `SELECT ?s WHERE { ?s a <http://example.org/SoftwareArchitect> }`,
  },
];

export function initQueryTab(el: HTMLElement): void {
  container = el;
  render();
}

function render(): void {
  container.innerHTML = `
    <div id="query-gate"></div>
    <div id="query-main" style="display:none">
      <div class="action-bar">
        <button class="btn btn-primary" id="btn-load-world">Load World State</button>
        <button class="btn" id="btn-load-trap">Load Entailment Trap</button>
      </div>
      <div id="triple-count" style="margin-bottom:1rem"></div>
      <div class="panel">
        <div class="panel-header">SPARQL Query</div>
        <div class="panel-body">
          <div style="margin-bottom:0.5rem;display:flex;gap:0.5rem;flex-wrap:wrap">
            ${EXAMPLE_QUERIES.map((q, i) => `<button class="btn" data-query-idx="${i}" style="font-size:0.75rem;padding:0.25rem 0.5rem">${q.label}</button>`).join("")}
          </div>
          <textarea class="form-input" id="sparql-input" rows="4">${EXAMPLE_QUERIES[0].sparql}</textarea>
          <div class="action-bar" style="margin-top:0.5rem">
            <button class="btn btn-primary" id="btn-execute">Execute Query</button>
          </div>
        </div>
      </div>
      <div id="query-results"></div>
      <div id="entailment-explanation" style="display:none"></div>
      <div class="transparency">
        <button class="transparency-toggle" id="hood-toggle-query">Under the Hood</button>
        <div class="transparency-content" id="hood-content-query"></div>
      </div>
    </div>
  `;

  checkGate();
}

function checkGate(): void {
  const gate = document.getElementById("query-gate")!;

  // Query tab works with or without Tab B data (can load entailment trap standalone)
  gate.innerHTML = "";
  document.getElementById("query-main")!.style.display = "block";

  // Wire events
  document.getElementById("btn-load-world")!.addEventListener("click", handleLoadWorld);
  document.getElementById("btn-load-trap")!.addEventListener("click", handleLoadTrap);
  document.getElementById("btn-execute")!.addEventListener("click", handleExecute);
  document.getElementById("hood-toggle-query")!.addEventListener("click", () => {
    document.getElementById("hood-content-query")!.classList.toggle("open");
  });

  // Query preset buttons
  container.querySelectorAll("[data-query-idx]").forEach(btn => {
    btn.addEventListener("click", () => {
      const idx = parseInt((btn as HTMLElement).dataset.queryIdx!);
      (document.getElementById("sparql-input") as HTMLTextAreaElement).value = EXAMPLE_QUERIES[idx].sparql;
    });
  });
}

async function handleLoadWorld(): Promise<void> {
  if (demoState.manifests.length === 0) {
    document.getElementById("query-results")!.innerHTML =
      `<div class="info-box warning">No signed content yet. Create content in Tab B first.</div>`;
    return;
  }

  const btn = document.getElementById("btn-load-world") as HTMLButtonElement;
  btn.disabled = true;
  btn.textContent = "Loading...";

  try {
    store = new OxigraphRDFStore();

    // Load all content from manifests
    for (const entry of demoState.manifests) {
      await store.load(entry.contentBytes, "application/ld+json", `hiri://${demoState.authority}/`);
    }

    document.getElementById("triple-count")!.innerHTML =
      `<div class="info-box success">Loaded ${store.tripleCount()} triples from ${demoState.manifests.length} manifest(s)</div>`;

    btn.textContent = "World Loaded";
  } catch (e) {
    btn.disabled = false;
    btn.textContent = "Load World State";
    document.getElementById("query-results")!.innerHTML =
      `<div class="info-box error">Load failed: ${(e as Error).message}</div>`;
  }
}

async function handleLoadTrap(): Promise<void> {
  const btn = document.getElementById("btn-load-trap") as HTMLButtonElement;
  btn.disabled = true;
  btn.textContent = "Loading...";

  try {
    store = new OxigraphRDFStore();
    const trapBytes = new TextEncoder().encode(JSON.stringify(ENTAILMENT_TRAP));
    await store.load(trapBytes, "application/ld+json", "http://example.org/");

    document.getElementById("triple-count")!.innerHTML =
      `<div class="info-box success">Loaded entailment trap: ${store.tripleCount()} triples</div>`;

    // Pre-fill the entailment query
    (document.getElementById("sparql-input") as HTMLTextAreaElement).value = EXAMPLE_QUERIES[3].sparql;

    // Show explanation
    showEntailmentExplanation();

    btn.textContent = "Trap Loaded";
  } catch (e) {
    btn.disabled = false;
    btn.textContent = "Load Entailment Trap";
    document.getElementById("query-results")!.innerHTML =
      `<div class="info-box error">Load failed: ${(e as Error).message}</div>`;
  }
}

function showEntailmentExplanation(): void {
  document.getElementById("entailment-explanation")!.style.display = "block";
  document.getElementById("entailment-explanation")!.innerHTML = `
    <div class="panel" style="margin-top:1rem">
      <div class="panel-header">Entailment Boundary Demonstrator</div>
      <div class="panel-body">
        <p style="font-size:0.85rem;margin-bottom:0.75rem">
          The fixture declares <code>ex:testSubject</code> as type <code>ex:SoftwareArchitect</code>,
          which is declared <code>rdfs:subClassOf schema:Person</code>.
        </p>
        <div class="info-box warning">
          Under entailment mode <strong>"none"</strong>, the engine does not follow
          <code>rdfs:subClassOf</code> relationships. This is deliberate — the entailment
          contract is <strong>enforced</strong>, not accidentally absent.
        </div>
        <p style="font-size:0.85rem;margin-top:0.75rem">
          Try these queries to see the boundary in action:
        </p>
        <ul style="font-size:0.8rem;color:var(--text-muted);margin-left:1.5rem">
          <li><code>SELECT ?s WHERE { ?s a &lt;http://schema.org/Person&gt; }</code> → <strong>0 results</strong> (no inference)</li>
          <li><code>SELECT ?s WHERE { ?s a &lt;http://example.org/SoftwareArchitect&gt; }</code> → <strong>1 result</strong> (explicit assertion)</li>
        </ul>
      </div>
    </div>
  `;
}

async function handleExecute(): Promise<void> {
  if (!store) {
    document.getElementById("query-results")!.innerHTML =
      `<div class="info-box warning">Load data first (World State or Entailment Trap).</div>`;
    return;
  }

  const sparql = (document.getElementById("sparql-input") as HTMLTextAreaElement).value.trim();
  if (!sparql) return;

  const btn = document.getElementById("btn-execute") as HTMLButtonElement;
  btn.disabled = true;
  btn.textContent = "Executing...";

  try {
    const result = await store.query(sparql, store);

    // Render results table
    const resultsDiv = document.getElementById("query-results")!;

    if (result.bindings.length === 0) {
      resultsDiv.innerHTML = `<div class="info-box info" style="margin-top:1rem">Query returned 0 results.</div>`;
    } else {
      const vars = Object.keys(result.bindings[0]);
      const headerRow = vars.map(v => `<th>${v}</th>`).join("");
      const bodyRows = result.bindings.map(row => {
        const cells = vars.map(v => {
          const term = row[v];
          if (!term) return "<td>-</td>";
          const display = term.type === "uri"
            ? `<span style="color:var(--accent)">&lt;${term.value}&gt;</span>`
            : `"${term.value}"${term.language ? `@${term.language}` : ""}`;
          return `<td>${display}</td>`;
        }).join("");
        return `<tr>${cells}</tr>`;
      }).join("");

      resultsDiv.innerHTML = `
        <div class="panel" style="margin-top:1rem">
          <div class="panel-header">Results (${result.bindings.length} rows)</div>
          <div class="panel-body">
            <table class="results-table">
              <thead><tr>${headerRow}</tr></thead>
              <tbody>${bodyRows}</tbody>
            </table>
          </div>
        </div>
      `;
    }

    // Update transparency
    document.getElementById("hood-content-query")!.innerHTML = `<pre>${stableStringify({
      query: sparql,
      tripleCount: store.tripleCount(),
      entailmentMode: "none",
      resultCount: result.bindings.length,
      truncated: result.truncated,
    }, true)}</pre>`;

    btn.disabled = false;
    btn.textContent = "Execute Query";
  } catch (e) {
    btn.disabled = false;
    btn.textContent = "Execute Query";
    document.getElementById("query-results")!.innerHTML =
      `<div class="info-box error" style="margin-top:1rem">SPARQL Error: ${(e as Error).message}</div>`;
  }
}
