rule Bypass_Sample_Pattern3
{
    meta:
        description = "Evasion bypass rule - Pattern 3"
        cape_options = "bp0=$pattern0+0,action0=skip,count=0"

    strings:
        $pattern0 = { 6A 00 51 8D B0 80 0C 00 00 56 50 E8 44 09 00 00 }

    condition:
        any of them
}