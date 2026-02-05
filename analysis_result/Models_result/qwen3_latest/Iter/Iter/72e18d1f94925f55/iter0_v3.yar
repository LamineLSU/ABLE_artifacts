rule ExampleRule
{
    meta:
        description = "Example rule to match specific assembly patterns"
        author = "Your Name"
        date = "2025-04-05"

    condition:
        (E8 ?? ?? ?? ?? 83 F8 01) or
        (83 F8 01 83 C4 04 01 C0) or
        (6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0)
}