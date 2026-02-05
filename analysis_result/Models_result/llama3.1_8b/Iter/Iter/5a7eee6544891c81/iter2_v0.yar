rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 85 C0 }
        $pattern1 = { FF 15 ?? ?? ?? ?? }

    condition:
        any of them
}