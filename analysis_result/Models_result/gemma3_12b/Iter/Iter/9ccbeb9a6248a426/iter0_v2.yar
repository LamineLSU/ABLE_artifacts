rule Bypass_Sample_3
{
    meta:
        description = "Evasion bypass rule - Call bypass"
        cape_options = "bp0=$pattern0+0,action0=skip"

    strings:
        $pattern0 = { FF 75 08 FF 15 AC B0 41 00 }

    condition:
        any of them
}