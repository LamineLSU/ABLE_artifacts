rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern0+10,action1=skip,bp2=$pattern1+0,action2=skip,count=0"

    strings:
        $pattern0 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C9 }
        $pattern1 = { 8B 4D FC 8B 55 F8 E8 ?? ?? ?? ?? }

    condition:
        any of them
}