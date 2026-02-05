rule ExampleRule
{
    meta:
        description = "Example YARA rule with three distinct patterns"
    
    strings:
        $p0 = { 50 FF 15 ?? ?? ?? ?? }
        $p1 = { 85 C0 0F 84 ?? ?? ?? ?? }
        $p2 = { FF 15 ?? ?? ?? ?? 33 FF }

    condition:
        all of them
}