rule Bypass_Sample_Pattern1
{
    meta:
        description = "Bypass call instruction at 0x001561F8 (Trace 1)"
        cape_options = "bp0=$pattern0+0,action0=skip"

    strings:
        $pattern0 = { 53 6A 40 53 68 40 11 15 FF 15 2C A1 15 00 }

    condition:
        all of them
}