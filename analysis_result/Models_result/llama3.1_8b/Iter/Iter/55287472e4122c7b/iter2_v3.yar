rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 83 C4 ?? }
        $pattern1 = { C3 00 74 ?? ?? E8 ?? ?? ?? ?? }
        $pattern2 = { DC 83 F9 FF 74 ?? E8 ?? ?? ?? ?? }

    condition:
        any of them
}