rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule - Bypass memory check"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern2 = { 8B CE E8 74 FA FF FF 85 C0 }

    condition:
        any of them
}