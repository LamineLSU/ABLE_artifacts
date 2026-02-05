rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 55 E8 ?? ?? ?? ?? FF 75 ?? }
        $pattern1 = { 83 EC 04 E9 ?? ?? ?? ?? 59 FF }
        $pattern2 = { C7 45 FC ?? ?? ?? ?? E8 ?? ?? ?? }

    condition:
        any of them
}