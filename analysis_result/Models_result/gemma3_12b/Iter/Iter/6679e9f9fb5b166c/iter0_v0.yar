rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8D 85 9C FD FF FF , 8B 85 9C FD FF FF , E8 D9 CE FF FF }
        $pattern1 = { 8D 95 80 FD FF FF , 33 C0 , E8 A5 91 FE FF }
        $pattern2 = { 6A 00 , 5A , 59 }

    condition:
        any of them
}