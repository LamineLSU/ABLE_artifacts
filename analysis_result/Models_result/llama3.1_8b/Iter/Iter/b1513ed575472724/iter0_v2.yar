rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=0,action1=pass,count=1"

    strings:
        $pattern0 = { 55 C9 E8 ?? ?? ?? ?? ?? ?? ?? }

    condition:
        any of them
}