rule ExampleRule
{
    meta:
        description = "Example rule with three patterns"

    strings:
        $a = { 81 C0 11 00 00 74 ?? }
        $b = { 85 C0 0F 84 ?? ?? ?? ?? }
        $c = { 6A 00 E8 ?? ?? ?? ?? 85 C0 }

    condition:
        all of them
}