rule Bypass_Sample_Trace1
{
    meta:
        description = "Evasion bypass rule - Trace 1"
        cape_options = "bp0=$pattern0+0,action0=skip"

    strings:
        $pattern0 = { 68 D0 07 00 00 FF 15 F0 41 41 00 }

    condition:
        any of them
}