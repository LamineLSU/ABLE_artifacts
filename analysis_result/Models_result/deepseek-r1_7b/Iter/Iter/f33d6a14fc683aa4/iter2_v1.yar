rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - improved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 E8 45 FC }
        $pattern1 = { 83 F8 74 12 E8 4D F8 }
        $pattern2 = { 8B 4F 74 12 E8 4E F8 }

    condition:
        any of them
}