rule Bypass_Sample_1
{
    meta:
        description = "Evasion bypass rule - Skip initial call edx"
        cape_options = "bp0=$pattern0+0,action0=skip"

    strings:
        $pattern0 = { 8B 91 80 00 00 00 FF ?? }

    condition:
        any of them
}