rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,count=0"

    strings:
        $pattern0 = { E8 C8 FF FF FF ?? ?? ?? ?? }
        $pattern1 = { FF 15 AC B0 41 00 ?? ?? ?? ?? }

    condition:
        any of them
}