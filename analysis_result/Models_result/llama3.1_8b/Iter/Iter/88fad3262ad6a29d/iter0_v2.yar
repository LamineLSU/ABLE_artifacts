rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,count=0"

    strings:
        $pattern0 = { FF 15 ?? ?? ?? ?? ?? FF 14 ?? ?? ?? ?? ?? E8 ?? ?? ?? }

    condition:
        any of them
}