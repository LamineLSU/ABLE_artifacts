rule Bypass_Sample
{
    meta:
        description = "Evasion bypass analysis patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 03 C3 }
        $pattern1 = { FF 75 08 E8 C8 FF FF }
        $pattern2 = { 85 C0 5A 8B EC E8 CF }

    condition:
        any of them
}