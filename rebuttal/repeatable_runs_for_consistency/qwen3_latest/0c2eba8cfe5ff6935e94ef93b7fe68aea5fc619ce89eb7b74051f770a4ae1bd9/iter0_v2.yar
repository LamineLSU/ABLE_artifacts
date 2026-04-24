rule ExampleRule
{
    meta:
        description = "Example rule with corrected patterns"
    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }
        $pattern1 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? }
        $pattern2 = { E8 ?? ?? ?? ?? 83 C4 ?? 50 }
    condition:
        all of them
}