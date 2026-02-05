rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip"

    strings:
        $pattern0 = { FF 15 ?? ?? ?? ?? 84 ?? 45 ?? }

    condition:
        any of them
}