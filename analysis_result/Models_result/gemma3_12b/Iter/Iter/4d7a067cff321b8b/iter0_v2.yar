rule Bypass_Sample_1
{
    meta:
        description = "Bypass call instruction - Trace 1 & 3"
        cape_options = "bp0=$pattern0+0,action0=skip,count=0"

    strings:
        $pattern0 = { 6A 40 53 E8 57 26 00 00 }

    condition:
        any of them
}