rule SandboxEvasion
{
    meta:
        description = "Detects potential sandbox evasion via API calls or indirect jumps."

    strings:
        $a = { 53 FF 15 ?? ?? ?? ?? 8B C7 }
        $b = { B9 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? }
        $c = { 33 C9 E8 B3 03 00 00 A1 ?? ?? ?? ?? }

    condition:
        any of ($a, $b, $c)
}