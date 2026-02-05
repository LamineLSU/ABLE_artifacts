rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule - CALL bypass (trace 3)"
        cape_options = "bp0=$pattern0+0,action0=skip,count=0"

    strings:
        $pattern0 = { E8 07 26 00 00 83 F8 01 74 20 64 A1 30 00 00 00 }

    condition:
        any of them
}