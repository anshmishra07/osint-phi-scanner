"""
Document/template fingerprinting.

MVP: normalized-token Jaccard similarity against tenant-registered reference
snippets (e.g., a known discharge-summary header, a report footer with the
org's confidential-marking boilerplate). Good enough to catch "this looks
like our template" without needing image/OCR fuzzy hashing yet.

PROD UPGRADE: for scanned/PDF/image templates, add perceptual hashing
(e.g. ImageHash) on rendered pages, and ssdeep/TLSH fuzzy hashing on raw
bytes for near-duplicate detection across reformatted copies.
"""
import re


def _tokenize(text: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]{3,}", text.lower()))


def fingerprint_similarity(candidate_text: str, reference_snippets: list[str]) -> tuple[float, str | None]:
    """Returns (best_similarity_0_to_1, matched_reference_snippet)."""
    cand_tokens = _tokenize(candidate_text)
    if not cand_tokens:
        return 0.0, None

    best_score = 0.0
    best_ref = None
    for ref in reference_snippets:
        ref_tokens = _tokenize(ref)
        if not ref_tokens:
            continue
        intersection = len(cand_tokens & ref_tokens)
        union = len(cand_tokens | ref_tokens)
        score = intersection / union if union else 0.0
        if score > best_score:
            best_score = score
            best_ref = ref

    return best_score, best_ref
