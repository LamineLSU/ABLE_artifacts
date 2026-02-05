rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC E8 F7 ?? ?? ?? ?? }
        $pattern1 = { 83 F8 01 74 12 8B 4D F8 5A E8 ?? ?? ?? ?? }
        $pattern2 = { 0F 31 F4 A1 E8 ?? ?? ?? ?? C9 59 }

    condition:
        any of them
}