rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule - First Call"
        cape_options = "bp0=$pattern0+0,action0=skip"

    strings:
        $pattern0 = { 77 0A FF 15 BC 36 61 00 }

    condition:
        any of them
}