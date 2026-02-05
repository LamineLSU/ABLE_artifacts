rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip"

    strings:
        $pattern0 = { 6A 04 68 00 30 00 00 68 C0 41 C8 17 }

    condition:
        any of them
}