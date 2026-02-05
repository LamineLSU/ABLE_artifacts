rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 F8 50 8B 4D 08 50 8B 4D DC 51 8B 55 08 }
        $pattern1 = { 8B 4D DC 51 8B 55 08 8B 45 F8 50 8B 4D 08 50 }
        $pattern2 = { 8B 4D DC 51 8B 55 08 8B 45 FC 50 8B 4D 08 8B 51 48 }

    condition:
        any of them
}