rule Bypass_Sample_1
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,count=0"

    strings:
        $pattern0 = { FF 15 AC B0 41 00 ?? ?? ?? FF 75 08 }
        $pattern1 = { 59 ?? FF 75 08 E8 C8 FF FF FF }

    condition:
        any of them
}