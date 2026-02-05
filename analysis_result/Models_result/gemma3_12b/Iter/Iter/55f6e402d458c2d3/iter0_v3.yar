rule Bypass_Trace1_InitialCall
{
    meta:
        description = "Bypass initial call in Trace 1"
        cape_options = "bp0=$pattern0+0,action0=skip"

    strings:
        $pattern0 = { 68 64 48 41 00 FF 15 20 41 41 00 }

    condition:
        any of them
}