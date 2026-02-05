rule Bypass_Sample1
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip"

    strings:
        $pattern0 = { 83 FA 05 ?? ?? ?? ?? 75 ?? }

    condition:
        any of them
}