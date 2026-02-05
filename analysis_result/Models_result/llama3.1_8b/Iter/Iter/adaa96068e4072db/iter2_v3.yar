rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B EC 83 C4 08 E8 ?? ?? ?? ?? 85 DB 78 04 }
        $pattern1 = { 3D 00 10 00 00 0F 82 ?? ?? }
        $pattern2 = { FF D0 6A 01 59 68 ?? ?? ?? ?? C7 45 FC }

    condition:
        any of them
}