rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,count=0"

    strings:
        $pattern0 = { FF D0 ?? ?? ?? FF D2 }
        $pattern1 = { FF D2 ?? ?? ?? FF D0 }

    condition:
        any of them
}