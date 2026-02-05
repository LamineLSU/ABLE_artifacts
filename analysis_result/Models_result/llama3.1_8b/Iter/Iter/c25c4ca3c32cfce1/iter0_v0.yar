rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B EC 83 C4 14 52 8B 16 FF D2 }
        $pattern1 = { B0 BF 35 58 22 FF E7 83 C4 14 }
        $pattern2 = { FF D0 5E 5D C3 8B EC B0 BF }

    condition:
        any of them
}