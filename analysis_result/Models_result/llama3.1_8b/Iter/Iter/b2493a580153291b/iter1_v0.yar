rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B E5 E8 ?? ?? ?? ?? 83 F8 01 74 12 }
        $pattern1 = { CA 83 C4 08 74 05 8B 45 FC E8 ?? ?? ?? ?? }
        $pattern2 = { EA EA 75 04 8B 45 FC E8 ?? ?? ?? ?? }

    condition:
        any of them
}