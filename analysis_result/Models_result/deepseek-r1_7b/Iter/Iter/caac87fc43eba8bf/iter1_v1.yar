rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting call instructions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 55 E8 C8 FFFFFF }
        $pattern1 = { 40E7FC E8 C8 FFFFFF }
        $pattern2 = { E8C8 F??? }

    condition:
        any of them
}