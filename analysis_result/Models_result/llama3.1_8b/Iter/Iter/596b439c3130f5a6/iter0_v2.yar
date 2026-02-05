rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,count=0"

    strings:
        $pattern0 = { 20 52 ?? ?? ?? FF D0 }
        $pattern1 = { 20 FF EE CE ?? C3 ?? ?? ?? }

    condition:
        any of them
}