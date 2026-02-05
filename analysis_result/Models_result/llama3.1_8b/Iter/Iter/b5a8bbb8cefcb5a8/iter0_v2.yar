rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip"

    strings:
        $pattern0 = { 55 8B EC E8 ?? ?? ?? ?? 85 C0 }

    condition:
        any of them
}