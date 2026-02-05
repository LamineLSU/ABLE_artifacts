rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$p1+0,action0=skip"

    strings:
        $p1 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 FC }

    condition:
        any of them
}