/**
 * Repository Evidence Graph Builder
 * Loads all chunk evidence documents from MongoDB, deduplicates nodes and edges,
 * preserves file paths, line numbers, snippets, and confidence scores,
 * and builds a queryable in-memory repository evidence graph.
 */
export class EvidenceGraphBuilder {
  /**
   * Loads evidence documents from MongoDB for analysisId and builds EvidenceGraph instance.
   * 
   * @param {Object} db - MongoDB database reference
   * @param {string} analysisId - Unique analysis ID
   * @returns {Promise<EvidenceGraph>} Unified in-memory Evidence Graph
   */
  static async buildRepositoryGraph(db, analysisId) {
    if (!db || !analysisId) {
      throw new Error('[EvidenceGraphBuilder] MongoDB reference and analysisId are required.');
    }

    const collection = db.collection('security_evidence');
    const evidenceDocs = await collection.find({ analysisId }).toArray();

    const nodeMap = new Map();
    const edgeMap = new Map();
    const frameworksSet = new Set();
    const importsSet = new Set();

    for (const doc of evidenceDocs) {
      if (Array.isArray(doc.frameworks)) {
        doc.frameworks.forEach((f) => frameworksSet.add(f));
      }
      if (Array.isArray(doc.imports)) {
        doc.imports.forEach((i) => importsSet.add(i));
      }

      const nodes = Array.isArray(doc.nodes) ? doc.nodes : [];
      for (const node of nodes) {
        // Unique node identifier
        const nodeKey = node.id || `${doc.filePath}:${node.rawId || node.name || 'node'}`;
        if (!nodeMap.has(nodeKey)) {
          nodeMap.set(nodeKey, {
            id: nodeKey,
            type: (node.type || 'UNKNOWN').toUpperCase(),
            file: node.file || doc.filePath,
            module: node.module || '',
            class: node.class || '',
            function: node.function || '',
            start_line: node.start_line || 1,
            end_line: node.end_line || 1,
            name: node.name || '',
            code: node.code || '',
            properties: node.properties || {},
            confidence: typeof node.confidence === 'number' ? node.confidence : 1.0,
            chunkId: doc.chunkId
          });
        } else {
          // Merge properties or update confidence if higher
          const existing = nodeMap.get(nodeKey);
          if (node.code && !existing.code) existing.code = node.code;
          if (typeof node.confidence === 'number' && node.confidence > existing.confidence) {
            existing.confidence = node.confidence;
          }
        }
      }

      const edges = Array.isArray(doc.edges) ? doc.edges : [];
      for (const edge of edges) {
        const edgeKey = `${edge.source}->${edge.relationship}->${edge.target}`;
        if (!edgeMap.has(edgeKey)) {
          edgeMap.set(edgeKey, {
            id: edgeKey,
            source: edge.source,
            relationship: (edge.relationship || 'USES').toUpperCase(),
            target: edge.target,
            confidence: typeof edge.confidence === 'number' ? edge.confidence : 1.0,
            chunkId: doc.chunkId
          });
        }
      }
    }

    const allNodes = Array.from(nodeMap.values());
    const allEdges = Array.from(edgeMap.values());
    const frameworks = Array.from(frameworksSet);
    const imports = Array.from(importsSet);

    return new EvidenceGraph(allNodes, allEdges, frameworks, imports, analysisId);
  }
}

/**
 * In-Memory Queryable Evidence Graph
 */
export class EvidenceGraph {
  constructor(nodes, edges, frameworks, imports, analysisId) {
    this.analysisId = analysisId;
    this.nodes = nodes;
    this.edges = edges;
    this.frameworks = frameworks;
    this.imports = imports;

    // Build indexes for fast O(1) domain queries
    this.nodesByType = new Map();
    this.nodeIndex = new Map();

    for (const node of nodes) {
      this.nodeIndex.set(node.id, node);
      const type = node.type;
      if (!this.nodesByType.has(type)) {
        this.nodesByType.set(type, []);
      }
      this.nodesByType.get(type).push(node);
    }
  }

  /**
   * Retrieves all nodes matching specified node types.
   * @param {Array<string>} types 
   * @returns {Array<Object>}
   */
  getNodesByTypes(types) {
    const uppercaseTypes = types.map((t) => t.toUpperCase());
    const matched = [];
    for (const type of uppercaseTypes) {
      if (this.nodesByType.has(type)) {
        matched.push(...this.nodesByType.get(type));
      }
    }
    return matched;
  }

  /**
   * Retrieves all edges associated with a set of node IDs.
   * @param {Set<string>|Array<string>} nodeIds 
   * @returns {Array<Object>}
   */
  getEdgesForNodes(nodeIds) {
    const idSet = nodeIds instanceof Set ? nodeIds : new Set(nodeIds);
    return this.edges.filter((edge) => idSet.has(edge.source) || idSet.has(edge.target));
  }
}
