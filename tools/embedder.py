"""Local embedding layer — the semantic half of hybrid retrieval.

Copied from rag-chunking-lab/shared/embedder.py so this project stays
self-contained. Uses a local sentence-transformers model (no API key, no
per-query cost). The model is lazy-loaded once and reused; vectors are
L2-normalized so cosine similarity is a plain dot product.
"""

import numpy as np
from sentence_transformers import SentenceTransformer

_model = None


def get_model():
    global _model
    if _model is None:
        _model = SentenceTransformer("sentence-transformers/all-mpnet-base-v2")
    return _model


def embed_texts(texts, batch_size=64):
    model = get_model()
    return model.encode(texts, batch_size=batch_size, normalize_embeddings=True)


def embed_query(text):
    return embed_texts([text])[0]


def cosine_similarity(a, b):
    return np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b) + 1e-10)
