rule ExampleRule
{
    meta:
        description = "Example rule with corrected patterns"

    strings:
        $a = { 8B 45 ?? E8 ?? ?? ?? ?? 85 C0 }
        $b = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $c = { E8 ?? ?? ?? ?? 85 C0 75 07 }

    condition:
        all of them
}