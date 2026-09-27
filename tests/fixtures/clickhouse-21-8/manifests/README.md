# ClickHouse 21.8 source manifest

`reference-orders-v001.json` and the fixture healthcheck pin
`expected_definition_sha256` to
`7f593054bebded05cba79194eaee4647731c4d3251a79fde0f2a3c6af44abb71`.
That value is the independently matched client/server SHA-256 of
`system.tables.create_table_query` observed from the pinned 21.8.15.7 fixture.
The integration gate must require this exact digest and must not derive a replacement
at runtime.
