rule Bypass_Sample_3
{
    meta:
        description = "Evasion bypass rule - Trace 2 - Comparison"
        cape_options = "bp0=$pattern0+0,action0=skip"

    strings:
        $pattern0 = { 83 3D BC 83 AB 00 01 75 06 FF 15 44 90 AB 00 }

    condition:
        any of them
}