rule ExampleRule
{
    meta:
        description = "Example rule with three different patterns"
    strings:
        $a = { 74 ?? 8B C0 FC 85 C9 }
        $b = { E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? }
        $c = { 85 D8 E8 ?? ?? ?? ?? }
    condition:
        all of them
}