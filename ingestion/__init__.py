"""Production ingestion pipeline — real scanner reports -> vector-DB records.

The seam the README promised, built out. Three concerns are kept independent
because real scanner exports vary along two axes at once:

    raw file --[parser]--> rows --[mapper]--> RecordMetadata --[builder]--> {id,text,metadata}
              (by ext)              (by scanner)                (screenshot shape)

- parsers/  : how to READ bytes into rows        (keyed by file extension)
- mappers/  : how to MAP rows to our schema      (keyed by scanner name)
- record_builder : RecordMetadata -> the {id, text, metadata} vector record
- manifest  : the envelope metadata a file can't self-describe (product, date, ...)

The same scanner exports in several formats, and the same format is used by every
scanner with different columns — so parser and mapper are separate registries,
not one function per (scanner x format).
"""
