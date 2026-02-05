rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 54 D3 FF FF 8D 85 4C F2 FF FF BA CC F6 34 02 }
        $pattern1 = { E8 E7 E9 FF FF 8B D0 8D 85 48 F2 FF FF }
        $pattern2 = { E8 72 E5 FF FF 8B 85 4C F2 FF FF 50 A1 AC 5B 35 02 }

    condition:
        any of them
}