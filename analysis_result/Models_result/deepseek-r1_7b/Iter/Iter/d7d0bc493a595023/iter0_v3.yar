rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting setup, call offset, and conditional checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B EC ?? ?? ?? ?? FF7508 FF1568F32000 }
        $pattern1 = { 8B EC ?? ?? ?? ?? FF7508 FF1568F38D00 }
        $pattern2 = { E8 C1F??? ?? ?? ?? ?? FF1568F??? ??? }
    condition:
        any of them
}