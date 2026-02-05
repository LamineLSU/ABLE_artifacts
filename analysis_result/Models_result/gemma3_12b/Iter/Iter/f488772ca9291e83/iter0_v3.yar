rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule - Skip another indirect call"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern2 = { A1 88 85 97 00 85 C0 74 07 50 FF 15 88 A0 97 00 }
    
    condition:
        any of them
}