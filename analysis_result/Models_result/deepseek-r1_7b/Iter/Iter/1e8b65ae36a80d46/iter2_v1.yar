rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting exit process calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 74 ?? ?? ?? ?? E8 EC FC }
        $pattern1 = { E8 EC ?? ?? ?? ?? FF C8 F3 }
        $pattern2 = { FF 15 AC B0 41 00 ?? ?? ?? ?? }

    condition:
        any of them
}