rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 50 51 FF D2 }
        $pattern1 = { 52 FF D0 5E }
        $pattern2 = { E5 62 7B ?? }

    condition:
        any of them
}