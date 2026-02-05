rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 55 8B EC E8 C1 FF FF 59 }
        $pattern1 = { 55 8B EC E8 C1 FF FF }
        $pattern2 = { 55 8B EC E8 C1 FF FF }

    condition:
        any of them
}