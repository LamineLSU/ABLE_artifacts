rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B EC 83 F8 01 74 12 8B 4D FC }
        $pattern1 = { C3 66 2E 0F 84 ?? ?? ?? ?? }
        $pattern2 = { FF D5 85 C0 75 E9 59 }

    condition:
        any of them
}