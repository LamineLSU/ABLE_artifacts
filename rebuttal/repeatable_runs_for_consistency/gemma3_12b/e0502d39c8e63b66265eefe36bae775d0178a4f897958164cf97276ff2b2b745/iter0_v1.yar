rule Bypass_Sample_3
{
    meta:
        description = "Evasion bypass rule - skipping function call"
        cape_options = "bp0=$pattern0+0,action0=skip,count=0"

    strings:
        $pattern0 = { 00 40 24 87 E8 3C 87 FF FF }

    condition:
        any of them
}