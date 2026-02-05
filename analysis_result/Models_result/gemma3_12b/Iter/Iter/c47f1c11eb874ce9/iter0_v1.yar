rule MalwareEvasionBypass
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 35 92 8D 56 FC 74 7D }
        $pattern1 = { 8B 06 52 5E 5D C3 }
        $pattern2 = { 50 51 FF D2 5E 5D }

    condition:
        any of them
}