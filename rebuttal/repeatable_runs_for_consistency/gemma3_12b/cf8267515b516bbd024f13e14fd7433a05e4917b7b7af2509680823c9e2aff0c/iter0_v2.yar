rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 7C 0C 00 00 85 18 56 50 }
        $pattern1 = { 3D 91 1E 8C F5 85 C0 40 }
        $pattern2 = { FF D0 5E 5D C3 40 }

    condition:
        any of them
}