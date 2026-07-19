"""ChromaDB vector store — the semantic index for hybrid retrieval.

Trimmed from rag-chunking-lab/vectordb/chroma_store.py. Bring-your-own-embeddings
mode: vectors are computed by tools.embedder and passed in explicitly. Uses an
in-memory (ephemeral) client — the findings corpus is tiny and rebuilt on start,
so there is no persistence to manage.

Note: search() returns cosine *distance* as `score` (lower = closer). The hybrid
fusion in rag_search only uses the *rank order* returned here, not the raw score,
so that distance-vs-similarity detail never leaks into the fused result.
"""

import chromadb


class ChromaStore:
    def __init__(self, collection_name="findings", persist_dir=None):
        if persist_dir:
            self.client = chromadb.PersistentClient(path=persist_dir)
        else:
            self.client = chromadb.EphemeralClient()
        self.collection_name = collection_name

        existing = [c.name for c in self.client.list_collections()]
        if collection_name in existing:
            self.client.delete_collection(collection_name)

        self.collection = self.client.create_collection(
            name=collection_name,
            metadata={"hnsw:space": "cosine"},
        )

    def add(self, chunks, embeddings):
        offset = self.collection.count()
        ids = [str(offset + i) for i in range(len(chunks))]
        documents = [c["text"] for c in chunks]
        metadatas = [c.get("metadata", {}) for c in chunks]

        clean_metadatas = []
        for m in metadatas:
            clean_metadatas.append({
                k: str(v) if not isinstance(v, (str, int, float, bool)) else v
                for k, v in m.items()
            })

        emb_list = [e.tolist() if hasattr(e, "tolist") else e for e in embeddings]

        self.collection.add(
            ids=ids,
            embeddings=emb_list,
            documents=documents,
            metadatas=clean_metadatas,
        )

    def search(self, query_embedding, k=5, where_filter=None):
        query = query_embedding.tolist() if hasattr(query_embedding, "tolist") else query_embedding
        kwargs = {"query_embeddings": [query], "n_results": k}
        if where_filter:
            kwargs["where"] = where_filter

        results = self.collection.query(**kwargs)
        hits = []
        for i in range(len(results["ids"][0])):
            hits.append({
                "text": results["documents"][0][i],
                "metadata": results["metadatas"][0][i] if results["metadatas"] else {},
                "score": results["distances"][0][i] if results["distances"] else 0.0,
            })
        return hits

    @property
    def count(self):
        return self.collection.count()
